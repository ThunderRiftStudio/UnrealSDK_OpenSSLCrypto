// OpenSSLCryptoMultiWorker.cpp
//
// CORRECTIF MSVC : les templates TWorkFn causaient une deduction en pointeur de
// fonction, incompatible avec les lambdas capturantes.
// Fix : chaque Activate() est ecrit directement, sans template.
// Les TArray<uint8> sont encapsules dans TSharedPtr pour etre copiables
// dans les captures de lambdas (AsyncTask requiert des lambdas copiables).

#include "OpenSSLCryptoMultiWorker.h"
#include "OpenSSLCryptoIncludes.h"
#include "Async/Async.h"
#include "Async/ParallelFor.h"
#include "HAL/PlatformMisc.h"
#include "HAL/PlatformTime.h"
#include "HAL/ThreadSafeBool.h"
#include "HAL/ThreadSafeCounter.h"
#include "HAL/ThreadSafeCounter64.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "HAL/PlatformFileManager.h"


// Constantes de format


namespace MWConst
{
	constexpr int64 MIN_CHUNK_BYTES = 256LL * 1024;

	static const uint8 MAGIC_PASSWORD[8] = { 0x89, 0x4F, 0x53, 0xC5, 0xAD, 0x0A, 0x50, 0x01 }; // non-printable, 0x50='P'
	static const uint8 MAGIC_RAWKEY[8]   = { 0x89, 0x4F, 0x53, 0xC5, 0xAD, 0x0A, 0x4B, 0x01 }; // non-printable, 0x4B='K'

	constexpr int32 HEADER_PASSWORD = 44;
	constexpr int32 HEADER_RAWKEY   = 28;
	constexpr int32 CHUNK_OVERHEAD  = 28; // IV(12) + TAG(16)

	constexpr float POLL_INTERVAL_SEC = 0.25f;
}


// Serialisation LE


static void WriteInt32LE(TArray<uint8>& Out, int32 V)
{
	Out.Add((uint8)(V        & 0xFF)); Out.Add((uint8)((V >> 8)  & 0xFF));
	Out.Add((uint8)((V >>16) & 0xFF)); Out.Add((uint8)((V >> 24) & 0xFF));
}
static void WriteInt64LE(TArray<uint8>& Out, int64 V)
{
	for (int32 i = 0; i < 8; i++) Out.Add((uint8)((V >> (i * 8)) & 0xFF));
}
static int32 ReadInt32LE(const uint8* D)
{
	return (int32)D[0] | ((int32)D[1]<<8) | ((int32)D[2]<<16) | ((int32)D[3]<<24);
}
static int64 ReadInt64LE(const uint8* D)
{
	int64 V = 0;
	for (int32 i = 0; i < 8; i++) V |= ((int64)D[i]) << (i * 8);
	return V;
}


// OpenSSL bas niveau


static bool MW_EncryptChunk(const uint8* Key, const uint8* Plain, int32 PlainLen,
	TArray<uint8>& OutChunk)
{
	uint8 IV[12];
	if (RAND_bytes(IV, 12) != 1) return false;

	EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
	if (!Ctx) return false;

	bool bOK = false;
	do
	{
		if (EVP_EncryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
		if (EVP_EncryptInit_ex(Ctx, nullptr, nullptr, Key, IV) != 1) break;

		TArray<uint8> Cipher;
		Cipher.SetNumUninitialized(PlainLen);
		if (PlainLen > 0)
		{
			int OL = 0;
			if (EVP_EncryptUpdate(Ctx, Cipher.GetData(), &OL, Plain, PlainLen) != 1) break;
			if (OL != PlainLen) break;
		}
		{ int FL = 0; if (EVP_EncryptFinal_ex(Ctx, nullptr, &FL) != 1) break; }

		uint8 Tag[16];
		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, 16, Tag) != 1) break;

		OutChunk.Empty(MWConst::CHUNK_OVERHEAD + PlainLen);
		OutChunk.Append(IV, 12);
		OutChunk.Append(Tag, 16);
		OutChunk.Append(Cipher);
		bOK = true;
	} while (false);

	EVP_CIPHER_CTX_free(Ctx);
	return bOK;
}

static bool MW_DecryptChunk(const uint8* Key, const uint8* ChunkData, int32 ChunkLen,
	TArray<uint8>& OutPlain)
{
	if (ChunkLen < MWConst::CHUNK_OVERHEAD) return false;

	const uint8* IV   = ChunkData;
	const uint8* Tag  = ChunkData + 12;
	const uint8* Ciph = ChunkData + MWConst::CHUNK_OVERHEAD;
	const int32  CLen = ChunkLen  - MWConst::CHUNK_OVERHEAD;

	EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
	if (!Ctx) return false;

	bool bOK = false;
	do
	{
		if (EVP_DecryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN, 12, nullptr) != 1) break;
		if (EVP_DecryptInit_ex(Ctx, nullptr, nullptr, Key, IV) != 1) break;

		OutPlain.SetNumUninitialized(CLen);
		if (CLen > 0) { int OL = 0; if (EVP_DecryptUpdate(Ctx, OutPlain.GetData(), &OL, Ciph, CLen) != 1) break; }

		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG, 16, const_cast<uint8*>(Tag)) != 1) break;
		{ int FL = 0; if (EVP_DecryptFinal_ex(Ctx, nullptr, &FL) <= 0) { EVP_CIPHER_CTX_free(Ctx); OutPlain.Empty(); return false; } }

		bOK = true;
	} while (false);

	EVP_CIPHER_CTX_free(Ctx);
	if (!bOK) OutPlain.Empty();
	return bOK;
}


// Etat partage (atomics)


struct FMWSharedState
{
	FThreadSafeCounter64 BytesDone;
	FThreadSafeCounter   ActiveWorkers;
	FThreadSafeCounter   ChunksDone;
	FThreadSafeBool      bPollerStop;
	// true pendant la derivation PBKDF2 (avant que ParallelFor commence)
	FThreadSafeBool      bKeyDerivation;

	int64  TotalBytes   = 0;
	int32  TotalChunks  = 0;
	int32  NumWorkers   = 0;
	int32  LogicalCores = 0;
	double StartTimeSec = 0.0;
};

static FOpenSSLCryptoProgress BuildProgress(const TSharedPtr<FMWSharedState>& S)
{
	FOpenSSLCryptoProgress P;
	const float  Elapsed = (float)(FPlatformTime::Seconds() - S->StartTimeSec);
	const int64  Done    = S->BytesDone.GetValue();
	const bool   bKD     = (bool)S->bKeyDerivation;
	P.ElapsedSeconds      = Elapsed;
	P.TotalMB             = (float)S->TotalBytes / 1048576.f;
	P.CurrentMB           = (float)Done          / 1048576.f;
	P.ProgressPercent     = S->TotalBytes > 0 ? FMath::Min(100.f, (float)Done / S->TotalBytes * 100.f) : 0.f;
	P.SpeedMBps           = (Elapsed > 0.001f && !bKD) ? P.CurrentMB / Elapsed : 0.f;
	P.WorkersActive       = S->ActiveWorkers.GetValue();
	P.NumChunks           = S->TotalChunks;
	P.ChunksDone          = S->ChunksDone.GetValue();
	P.CPUUsedPercent      = S->LogicalCores > 0 ? FMath::Min(100.f, (float)P.WorkersActive / S->LogicalCores * 100.f) : 0.f;
	P.bKeyDerivationPhase = bKD;
	return P;
}



// Utilitaires


static int32 GetNumWorkers(EOpenSSLWorkerMode Mode)
{
	const int32 C = FMath::Max(1, FPlatformMisc::NumberOfCores());
	switch (Mode)
	{
		case EOpenSSLWorkerMode::Low:  return FMath::Max(1, C / 2);
		case EOpenSSLWorkerMode::High: return FMath::Max(1, C - 1);
		case EOpenSSLWorkerMode::Max:  return C;
		default:                       return FMath::Max(1, C - 1);
	}
}

static void CalcChunking(int64 Total, int32 Workers, int64& OutSize, int32& OutNum)
{
	OutSize = FMath::Max(MWConst::MIN_CHUNK_BYTES, (Total + Workers - 1) / Workers);
	OutNum  = OutSize > 0 ? FMath::Max(1, (int32)FMath::CeilToInt64((double)Total / OutSize)) : 1;
}

static bool MW_DeriveKey(const FString& Password, const uint8* Salt, int32 SaltLen,
	int32 Iterations, uint8* OutKey32)
{
	FTCHARToUTF8 UTF8(*Password);
	return PKCS5_PBKDF2_HMAC(
		reinterpret_cast<const char*>(UTF8.Get()), UTF8.Length(),
		Salt, SaltLen, Iterations, EVP_sha256(), 32, OutKey32) == 1;
}

static bool MW_ReadFile(const FString& Path, TArray<uint8>& Out, FString& Err)
{
	IPlatformFile& PF = FPlatformFileManager::Get().GetPlatformFile();
	if (!PF.FileExists(*Path)) { Err = FString::Printf(TEXT("Fichier introuvable : %s"), *Path); return false; }
	if (!FFileHelper::LoadFileToArray(Out, *Path)) { Err = FString::Printf(TEXT("Lecture impossible : %s"), *Path); return false; }
	return true;
}

static bool MW_WriteFile(const FString& Path, const TArray<uint8>& Data, FString& Err)
{
	const FString Dir = FPaths::GetPath(Path);
	if (!Dir.IsEmpty())
	{
		IPlatformFile& PF = FPlatformFileManager::Get().GetPlatformFile();
		if (!PF.DirectoryExists(*Dir) && !PF.CreateDirectoryTree(*Dir))
		{ Err = FString::Printf(TEXT("Impossible de creer le dossier : %s"), *Dir); return false; }
	}
	if (!FFileHelper::SaveArrayToFile(Data, *Path)) { Err = FString::Printf(TEXT("Ecriture impossible : %s"), *Path); return false; }
	return true;
}


// Cores MW (travail reel, appelees depuis le coordinateur)


static FOpenSSLCryptoResult MW_DoEncrypt_Password(
	const TArray<uint8>& Plaintext, const FString& Password,
	int32 Iterations, TSharedPtr<FMWSharedState> State)
{
	ERR_clear_error();
	const int64 TotalSize = Plaintext.Num();

	uint8 Salt[16];
	if (RAND_bytes(Salt, 16) != 1) return { false, TEXT("RAND_bytes (salt) echoue."), {} };

	uint8 Key[32]; FMemory::Memzero(Key, 32);
	if (!MW_DeriveKey(Password, Salt, 16, Iterations, Key))
	{ FMemory::Memzero(Key, 32); return { false, TEXT("PBKDF2 echoue."), {} }; }

	int64 ChunkSize; int32 NumChunks;
	CalcChunking(TotalSize, State->NumWorkers, ChunkSize, NumChunks);
	State->TotalChunks = NumChunks;

	TArray<TArray<uint8>> ChunkResults; ChunkResults.SetNum(NumChunks);
	TArray<bool> ChunkOK; ChunkOK.Init(false, NumChunks);

	ParallelFor(NumChunks, [&](int32 i)
	{
		State->ActiveWorkers.Increment();
		const int64 Offset = (int64)i * ChunkSize;
		const int32 Size   = (int32)FMath::Min(ChunkSize, TotalSize - Offset);
		ChunkOK[i] = MW_EncryptChunk(Key, Plaintext.GetData() + Offset, Size, ChunkResults[i]);
		State->BytesDone.Add(Size);
		State->ChunksDone.Increment();
		State->ActiveWorkers.Decrement();
	});

	FMemory::Memzero(Key, 32);

	for (int32 i = 0; i < NumChunks; i++)
		if (!ChunkOK[i]) return { false, FString::Printf(TEXT("Chunk %d echoue."), i), {} };

	// Assembler header + chunks
	TArray<uint8> Output;
	Output.Reserve(MWConst::HEADER_PASSWORD + (int32)TotalSize + NumChunks * MWConst::CHUNK_OVERHEAD);
	Output.Append(MWConst::MAGIC_PASSWORD, 8);
	Output.Append(Salt, 16);
	WriteInt64LE(Output, TotalSize);
	WriteInt32LE(Output, NumChunks);
	WriteInt64LE(Output, ChunkSize);
	for (int32 i = 0; i < NumChunks; i++) Output.Append(ChunkResults[i]);

	return { true, FString(), MoveTemp(Output) };
}

static FOpenSSLCryptoResult MW_DoDecrypt_Password(
	const TArray<uint8>& Encrypted, const FString& Password,
	int32 Iterations, TSharedPtr<FMWSharedState> State)
{
	ERR_clear_error();

	if (Encrypted.Num() < MWConst::HEADER_PASSWORD ||
		FMemory::Memcmp(Encrypted.GetData(), MWConst::MAGIC_PASSWORD, 8) != 0)
		return { false, TEXT("Magic invalide (attendu OSCMWP01)."), {} };

	const uint8* Ptr       = Encrypted.GetData() + 8;
	const uint8* Salt      = Ptr; Ptr += 16;
	const int64  TotalSize = ReadInt64LE(Ptr); Ptr += 8;
	const int32  NumChunks = ReadInt32LE(Ptr); Ptr += 4;
	const int64  ChunkSize = ReadInt64LE(Ptr); Ptr += 8;

	if (NumChunks <= 0 || ChunkSize <= 0 || TotalSize < 0)
		return { false, TEXT("Header MW corrompu."), {} };

	// Fixer TotalBytes AVANT PBKDF2 pour que le poller affiche la bonne valeur
	State->TotalBytes  = TotalSize;
	State->TotalChunks = NumChunks;

	// Signaler la phase de derivation de cle (PBKDF2 bloque ~100ms)
	State->bKeyDerivation = true;
	uint8 Key[32]; FMemory::Memzero(Key, 32);
	if (!MW_DeriveKey(Password, Salt, 16, Iterations, Key))
	{ FMemory::Memzero(Key, 32); State->bKeyDerivation = false; return { false, TEXT("PBKDF2 echoue."), {} }; }
	State->bKeyDerivation = false;

	TArray<int64> ChunkOffsets; ChunkOffsets.SetNum(NumChunks);
	TArray<int32> ChunkLens;   ChunkLens.SetNum(NumChunks);
	int64 DataOffset = (int64)(Ptr - Encrypted.GetData());
	for (int32 i = 0; i < NumChunks; i++)
	{
		const int64 PLen = FMath::Min(ChunkSize, TotalSize - (int64)i * ChunkSize);
		ChunkOffsets[i]  = DataOffset;
		ChunkLens[i]     = MWConst::CHUNK_OVERHEAD + (int32)PLen;
		DataOffset      += ChunkLens[i];
	}
	if (DataOffset > Encrypted.Num())
	{ FMemory::Memzero(Key, 32); return { false, TEXT("Payload trop court."), {} }; }

	TArray<uint8> Plaintext; Plaintext.SetNumUninitialized((int32)TotalSize);
	TArray<bool> ChunkOK; ChunkOK.Init(false, NumChunks);

	ParallelFor(NumChunks, [&](int32 i)
	{
		State->ActiveWorkers.Increment();
		TArray<uint8> PlainChunk;
		ChunkOK[i] = MW_DecryptChunk(Key, Encrypted.GetData() + ChunkOffsets[i], ChunkLens[i], PlainChunk);
		if (ChunkOK[i])
			FMemory::Memcpy(Plaintext.GetData() + (int64)i * ChunkSize, PlainChunk.GetData(), PlainChunk.Num());
		State->BytesDone.Add(ChunkLens[i] - MWConst::CHUNK_OVERHEAD);
		State->ChunksDone.Increment();
		State->ActiveWorkers.Decrement();
	});

	FMemory::Memzero(Key, 32);
	for (int32 i = 0; i < NumChunks; i++)
		if (!ChunkOK[i]) return { false, FString::Printf(TEXT("Chunk %d : tag invalide."), i), {} };

	return { true, FString(), MoveTemp(Plaintext) };
}

static FOpenSSLCryptoResult MW_DoEncrypt_RawKey(
	const TArray<uint8>& Plaintext, const TArray<uint8>& Key,
	TSharedPtr<FMWSharedState> State)
{
	ERR_clear_error();
	if (Key.Num() != 32) return { false, TEXT("RawKey32 doit faire 32 octets."), {} };

	const int64 TotalSize = Plaintext.Num();
	int64 ChunkSize; int32 NumChunks;
	CalcChunking(TotalSize, State->NumWorkers, ChunkSize, NumChunks);
	State->TotalChunks = NumChunks;

	TArray<TArray<uint8>> ChunkResults; ChunkResults.SetNum(NumChunks);
	TArray<bool> ChunkOK; ChunkOK.Init(false, NumChunks);

	ParallelFor(NumChunks, [&](int32 i)
	{
		State->ActiveWorkers.Increment();
		const int64 Offset = (int64)i * ChunkSize;
		const int32 Size   = (int32)FMath::Min(ChunkSize, TotalSize - Offset);
		ChunkOK[i] = MW_EncryptChunk(Key.GetData(), Plaintext.GetData() + Offset, Size, ChunkResults[i]);
		State->BytesDone.Add(Size);
		State->ChunksDone.Increment();
		State->ActiveWorkers.Decrement();
	});

	for (int32 i = 0; i < NumChunks; i++)
		if (!ChunkOK[i]) return { false, FString::Printf(TEXT("Chunk %d echoue."), i), {} };

	TArray<uint8> Output;
	Output.Reserve(MWConst::HEADER_RAWKEY + (int32)TotalSize + NumChunks * MWConst::CHUNK_OVERHEAD);
	Output.Append(MWConst::MAGIC_RAWKEY, 8);
	WriteInt64LE(Output, TotalSize);
	WriteInt32LE(Output, NumChunks);
	WriteInt64LE(Output, ChunkSize);
	for (auto& C : ChunkResults) Output.Append(C);

	return { true, FString(), MoveTemp(Output) };
}

static FOpenSSLCryptoResult MW_DoDecrypt_RawKey(
	const TArray<uint8>& Encrypted, const TArray<uint8>& Key,
	TSharedPtr<FMWSharedState> State)
{
	ERR_clear_error();
	if (Key.Num() != 32) return { false, TEXT("RawKey32 doit faire 32 octets."), {} };

	if (Encrypted.Num() < MWConst::HEADER_RAWKEY ||
		FMemory::Memcmp(Encrypted.GetData(), MWConst::MAGIC_RAWKEY, 8) != 0)
		return { false, TEXT("Magic invalide (attendu OSCMWK01)."), {} };

	const uint8* Ptr       = Encrypted.GetData() + 8;
	const int64  TotalSize = ReadInt64LE(Ptr); Ptr += 8;
	const int32  NumChunks = ReadInt32LE(Ptr); Ptr += 4;
	const int64  ChunkSize = ReadInt64LE(Ptr); Ptr += 8;

	if (NumChunks <= 0 || ChunkSize <= 0 || TotalSize < 0)
		return { false, TEXT("Header MW corrompu."), {} };

	// Fixer TotalBytes des maintenant pour que le poller soit correct
	State->TotalBytes  = TotalSize;
	State->TotalChunks = NumChunks;

	TArray<int64> ChunkOffsets; ChunkOffsets.SetNum(NumChunks);
	TArray<int32> ChunkLens;   ChunkLens.SetNum(NumChunks);
	int64 DataOffset = (int64)(Ptr - Encrypted.GetData());
	for (int32 i = 0; i < NumChunks; i++)
	{
		const int64 PLen = FMath::Min(ChunkSize, TotalSize - (int64)i * ChunkSize);
		ChunkOffsets[i]  = DataOffset;
		ChunkLens[i]     = MWConst::CHUNK_OVERHEAD + (int32)PLen;
		DataOffset      += ChunkLens[i];
	}
	if (DataOffset > Encrypted.Num())
		return { false, TEXT("Payload trop court."), {} };

	TArray<uint8> Plaintext; Plaintext.SetNumUninitialized((int32)TotalSize);
	TArray<bool> ChunkOK; ChunkOK.Init(false, NumChunks);

	ParallelFor(NumChunks, [&](int32 i)
	{
		State->ActiveWorkers.Increment();
		TArray<uint8> PlainChunk;
		ChunkOK[i] = MW_DecryptChunk(Key.GetData(), Encrypted.GetData() + ChunkOffsets[i], ChunkLens[i], PlainChunk);
		if (ChunkOK[i])
			FMemory::Memcpy(Plaintext.GetData() + (int64)i * ChunkSize, PlainChunk.GetData(), PlainChunk.Num());
		State->BytesDone.Add(ChunkLens[i] - MWConst::CHUNK_OVERHEAD);
		State->ChunksDone.Increment();
		State->ActiveWorkers.Decrement();
	});

	for (int32 i = 0; i < NumChunks; i++)
		if (!ChunkOK[i]) return { false, FString::Printf(TEXT("Chunk %d : tag invalide."), i), {} };

	return { true, FString(), MoveTemp(Plaintext) };
}


// Macro helper pour le poller (identique dans tous les Activate)

// NOTE : on ne peut pas utiliser de template car AsyncTask requiert des lambdas
// copiables. On encapsule les TArray<uint8> dans TSharedPtr pour les rendre
// copiables dans les captures.

#define MW_START_POLLER(StateVar, WeakNodeVar) \
	Async(EAsyncExecution::Thread, [StateVar, WeakNodeVar]() \
	{ \
		while (!StateVar->bPollerStop) \
		{ \
			FPlatformProcess::Sleep(MWConst::POLL_INTERVAL_SEC); \
			if (StateVar->bPollerStop) break; \
			FOpenSSLCryptoProgress P = BuildProgress(StateVar); \
			AsyncTask(ENamedThreads::GameThread, [WeakNodeVar, P]() \
			{ \
				if (WeakNodeVar.IsValid()) WeakNodeVar->OnProgress.Broadcast(TArray<uint8>(), FString(), P); \
			}); \
		} \
	});

// Poller pour noeuds File — FOnMWFileEvent a 2 params (ErrorMessage, Progress)
// FOnMWBytesEvent en a 3 (Data, ErrorMessage, Progress) — les deux macros sont necessaires.
#define MW_START_POLLER_FILE(StateVar, WeakNodeVar) \
	Async(EAsyncExecution::Thread, [StateVar, WeakNodeVar]() \
	{ \
		while (!StateVar->bPollerStop) \
		{ \
			FPlatformProcess::Sleep(MWConst::POLL_INTERVAL_SEC); \
			if (StateVar->bPollerStop) break; \
			FOpenSSLCryptoProgress P = BuildProgress(StateVar); \
			AsyncTask(ENamedThreads::GameThread, [WeakNodeVar, P]() \
			{ \
				if (WeakNodeVar.IsValid()) WeakNodeVar->OnProgress.Broadcast(FString(), P); \
			}); \
		} \
	});


// Helper pour dispatcher le resultat bytes sur le Game Thread


template<typename TNode>
static void MW_DispatchBytesResult(
	TWeakObjectPtr<TNode>       WeakNode,
	FOpenSSLCryptoResult&&      Result,
	TSharedPtr<FMWSharedState>  State)
{
	State->bPollerStop = true;
	FOpenSSLCryptoProgress FinalP = BuildProgress(State);
	if (Result.bSuccess) FinalP.ProgressPercent = 100.f;

	if (Result.bSuccess)
	{
		// Wrap Data dans TSharedPtr pour capture copiable
		TSharedPtr<TArray<uint8>> DataPtr = MakeShared<TArray<uint8>>(MoveTemp(Result.Data));
		AsyncTask(ENamedThreads::GameThread, [WeakNode, DataPtr, FinalP]()
		{
			if (WeakNode.IsValid())
				WeakNode->OnSuccess.Broadcast(*DataPtr, FString(), FinalP);
		});
	}
	else
	{
		FString Err = Result.ErrorMessage;
		AsyncTask(ENamedThreads::GameThread, [WeakNode, Err, FinalP]()
		{
			if (WeakNode.IsValid())
				WeakNode->OnFailure.Broadcast(TArray<uint8>(), Err, FinalP);
		});
	}
}

template<typename TNode>
static void MW_DispatchFileResult(
	TWeakObjectPtr<TNode>       WeakNode,
	const FString&              OutputPath,
	FOpenSSLCryptoResult&&      Result,
	TSharedPtr<FMWSharedState>  State)
{
	State->bPollerStop = true;
	FOpenSSLCryptoProgress FinalP = BuildProgress(State);
	if (Result.bSuccess) FinalP.ProgressPercent = 100.f;

	if (!Result.bSuccess)
	{
		FString Err = Result.ErrorMessage;
		AsyncTask(ENamedThreads::GameThread, [WeakNode, Err, FinalP]()
		{
			if (WeakNode.IsValid()) WeakNode->OnFailure.Broadcast(Err, FinalP);
		});
		return;
	}

	// Ecrire sur disque (encore sur le thread coordinateur, pas le GT)
	TSharedPtr<TArray<uint8>> DataPtr = MakeShared<TArray<uint8>>(MoveTemp(Result.Data));
	FString WriteErr;
	if (!MW_WriteFile(OutputPath, *DataPtr, WriteErr))
	{
		AsyncTask(ENamedThreads::GameThread, [WeakNode, WriteErr, FinalP]()
		{
			if (WeakNode.IsValid()) WeakNode->OnFailure.Broadcast(WriteErr, FinalP);
		});
		return;
	}

	AsyncTask(ENamedThreads::GameThread, [WeakNode, FinalP]()
	{
		if (WeakNode.IsValid()) WeakNode->OnSuccess.Broadcast(FString(), FinalP);
	});
}


// Activate() — MW Encrypt Bytes Password


UAsyncMW_EncryptBytes_Password* UAsyncMW_EncryptBytes_Password::MW_EncryptBytes_AES256GCM(
	const TArray<uint8>& InPlaintext, const FString& InPassword,
	EOpenSSLWorkerMode InMode, int32 InIterations)
{
	auto* Node = NewObject<UAsyncMW_EncryptBytes_Password>();
	Node->Plaintext  = InPlaintext;
	Node->Password   = InPassword;
	Node->WorkerMode = InMode;
	Node->Iterations = InIterations;
	return Node;
}

void UAsyncMW_EncryptBytes_Password::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->TotalBytes   = Plaintext.Num();
	State->StartTimeSec = FPlatformTime::Seconds();

	// Encapsuler TArray dans TSharedPtr pour capture copiable dans AsyncTask
	TSharedPtr<TArray<uint8>> PlainPtr = MakeShared<TArray<uint8>>(MoveTemp(Plaintext));
	FString  Pass = Password;
	int32    Iter = Iterations;

	TWeakObjectPtr<UAsyncMW_EncryptBytes_Password> WeakThis(this);

	MW_START_POLLER(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, PlainPtr, Pass, Iter]()
	{
		FOpenSSLCryptoResult R = MW_DoEncrypt_Password(*PlainPtr, Pass, Iter, State);
		MW_DispatchBytesResult(WeakThis, MoveTemp(R), State);
	});
}


// Activate() — MW Decrypt Bytes Password


UAsyncMW_DecryptBytes_Password* UAsyncMW_DecryptBytes_Password::MW_DecryptBytes_AES256GCM(
	const TArray<uint8>& InEncrypted, const FString& InPassword,
	EOpenSSLWorkerMode InMode, int32 InIterations)
{
	auto* Node = NewObject<UAsyncMW_DecryptBytes_Password>();
	Node->EncryptedPayload = InEncrypted;
	Node->Password         = InPassword;
	Node->WorkerMode       = InMode;
	Node->Iterations       = InIterations;
	return Node;
}

void UAsyncMW_DecryptBytes_Password::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	// TotalBytes = 0 : sera corrige par MW_DoDecrypt_* apres parsing header,
	// avant ParallelFor. Evite un pourcentage faux pendant le parsing/PBKDF2.
	State->TotalBytes   = 0;
	State->StartTimeSec = FPlatformTime::Seconds();

	TSharedPtr<TArray<uint8>> EncPtr = MakeShared<TArray<uint8>>(MoveTemp(EncryptedPayload));
	FString Pass = Password;
	int32   Iter = Iterations;

	TWeakObjectPtr<UAsyncMW_DecryptBytes_Password> WeakThis(this);

	MW_START_POLLER(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, EncPtr, Pass, Iter]()
	{
		FOpenSSLCryptoResult R = MW_DoDecrypt_Password(*EncPtr, Pass, Iter, State);
		MW_DispatchBytesResult(WeakThis, MoveTemp(R), State);
	});
}


// Activate() — MW Encrypt Bytes RawKey


UAsyncMW_EncryptBytes_RawKey* UAsyncMW_EncryptBytes_RawKey::MW_EncryptBytes_AES256GCM_RawKey(
	const TArray<uint8>& InPlaintext, const TArray<uint8>& InKey, EOpenSSLWorkerMode InMode)
{
	auto* Node = NewObject<UAsyncMW_EncryptBytes_RawKey>();
	Node->Plaintext  = InPlaintext;
	Node->RawKey32   = InKey;
	Node->WorkerMode = InMode;
	return Node;
}

void UAsyncMW_EncryptBytes_RawKey::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->TotalBytes   = Plaintext.Num();
	State->StartTimeSec = FPlatformTime::Seconds();

	TSharedPtr<TArray<uint8>> PlainPtr = MakeShared<TArray<uint8>>(MoveTemp(Plaintext));
	TSharedPtr<TArray<uint8>> KeyPtr   = MakeShared<TArray<uint8>>(RawKey32); // copie cle

	TWeakObjectPtr<UAsyncMW_EncryptBytes_RawKey> WeakThis(this);

	MW_START_POLLER(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, PlainPtr, KeyPtr]()
	{
		FOpenSSLCryptoResult R = MW_DoEncrypt_RawKey(*PlainPtr, *KeyPtr, State);
		MW_DispatchBytesResult(WeakThis, MoveTemp(R), State);
	});
}


// Activate() — MW Decrypt Bytes RawKey


UAsyncMW_DecryptBytes_RawKey* UAsyncMW_DecryptBytes_RawKey::MW_DecryptBytes_AES256GCM_RawKey(
	const TArray<uint8>& InEncrypted, const TArray<uint8>& InKey, EOpenSSLWorkerMode InMode)
{
	auto* Node = NewObject<UAsyncMW_DecryptBytes_RawKey>();
	Node->EncryptedPayload = InEncrypted;
	Node->RawKey32         = InKey;
	Node->WorkerMode       = InMode;
	return Node;
}

void UAsyncMW_DecryptBytes_RawKey::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->TotalBytes   = 0; // sera corrige par MW_DoDecrypt_* avant ParallelFor
	State->StartTimeSec = FPlatformTime::Seconds();

	TSharedPtr<TArray<uint8>> EncPtr = MakeShared<TArray<uint8>>(MoveTemp(EncryptedPayload));
	TSharedPtr<TArray<uint8>> KeyPtr = MakeShared<TArray<uint8>>(RawKey32);

	TWeakObjectPtr<UAsyncMW_DecryptBytes_RawKey> WeakThis(this);

	MW_START_POLLER(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, EncPtr, KeyPtr]()
	{
		FOpenSSLCryptoResult R = MW_DoDecrypt_RawKey(*EncPtr, *KeyPtr, State);
		MW_DispatchBytesResult(WeakThis, MoveTemp(R), State);
	});
}


// Activate() — MW Encrypt File Password


UAsyncMW_EncryptFile_Password* UAsyncMW_EncryptFile_Password::MW_EncryptFile_AES256GCM(
	const FString& In, const FString& Out, const FString& Pass,
	EOpenSSLWorkerMode Mode, int32 Iter)
{
	auto* Node = NewObject<UAsyncMW_EncryptFile_Password>();
	Node->InputFilePath  = In;
	Node->OutputFilePath = Out;
	Node->Password       = Pass;
	Node->WorkerMode     = Mode;
	Node->Iterations     = Iter;
	return Node;
}

void UAsyncMW_EncryptFile_Password::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->StartTimeSec = FPlatformTime::Seconds();

	FString InPath  = InputFilePath;
	FString OutPath = OutputFilePath;
	FString Pass    = Password;
	int32   Iter    = Iterations;

	TWeakObjectPtr<UAsyncMW_EncryptFile_Password> WeakThis(this);

	MW_START_POLLER_FILE(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, InPath, OutPath, Pass, Iter]()
	{
		TArray<uint8> Bytes; FString RE;
		if (!MW_ReadFile(InPath, Bytes, RE))
		{
			State->bPollerStop = true;
			FOpenSSLCryptoProgress P = BuildProgress(State);
			AsyncTask(ENamedThreads::GameThread, [WeakThis, RE, P]()
			{ if (WeakThis.IsValid()) WeakThis->OnFailure.Broadcast(RE, P); });
			return;
		}
		State->TotalBytes = Bytes.Num();
		FOpenSSLCryptoResult R = MW_DoEncrypt_Password(Bytes, Pass, Iter, State);
		MW_DispatchFileResult(WeakThis, OutPath, MoveTemp(R), State);
	});
}


// Activate() — MW Decrypt File Password


UAsyncMW_DecryptFile_Password* UAsyncMW_DecryptFile_Password::MW_DecryptFile_AES256GCM(
	const FString& In, const FString& Out, const FString& Pass,
	EOpenSSLWorkerMode Mode, int32 Iter)
{
	auto* Node = NewObject<UAsyncMW_DecryptFile_Password>();
	Node->InputFilePath  = In;
	Node->OutputFilePath = Out;
	Node->Password       = Pass;
	Node->WorkerMode     = Mode;
	Node->Iterations     = Iter;
	return Node;
}

void UAsyncMW_DecryptFile_Password::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->StartTimeSec = FPlatformTime::Seconds();

	FString InPath  = InputFilePath;
	FString OutPath = OutputFilePath;
	FString Pass    = Password;
	int32   Iter    = Iterations;

	TWeakObjectPtr<UAsyncMW_DecryptFile_Password> WeakThis(this);

	MW_START_POLLER_FILE(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, InPath, OutPath, Pass, Iter]()
	{
		TArray<uint8> Bytes; FString RE;
		if (!MW_ReadFile(InPath, Bytes, RE))
		{
			State->bPollerStop = true;
			FOpenSSLCryptoProgress P = BuildProgress(State);
			AsyncTask(ENamedThreads::GameThread, [WeakThis, RE, P]()
			{ if (WeakThis.IsValid()) WeakThis->OnFailure.Broadcast(RE, P); });
			return;
		}
		State->TotalBytes = Bytes.Num();
		FOpenSSLCryptoResult R = MW_DoDecrypt_Password(Bytes, Pass, Iter, State);
		MW_DispatchFileResult(WeakThis, OutPath, MoveTemp(R), State);
	});
}


// Activate() — MW Encrypt File RawKey


UAsyncMW_EncryptFile_RawKey* UAsyncMW_EncryptFile_RawKey::MW_EncryptFile_AES256GCM_RawKey(
	const FString& In, const FString& Out, const TArray<uint8>& Key, EOpenSSLWorkerMode Mode)
{
	auto* Node = NewObject<UAsyncMW_EncryptFile_RawKey>();
	Node->InputFilePath  = In;
	Node->OutputFilePath = Out;
	Node->RawKey32       = Key;
	Node->WorkerMode     = Mode;
	return Node;
}

void UAsyncMW_EncryptFile_RawKey::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->StartTimeSec = FPlatformTime::Seconds();

	FString InPath  = InputFilePath;
	FString OutPath = OutputFilePath;
	TSharedPtr<TArray<uint8>> KeyPtr = MakeShared<TArray<uint8>>(RawKey32);

	TWeakObjectPtr<UAsyncMW_EncryptFile_RawKey> WeakThis(this);

	MW_START_POLLER_FILE(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, InPath, OutPath, KeyPtr]()
	{
		TArray<uint8> Bytes; FString RE;
		if (!MW_ReadFile(InPath, Bytes, RE))
		{
			State->bPollerStop = true;
			FOpenSSLCryptoProgress P = BuildProgress(State);
			AsyncTask(ENamedThreads::GameThread, [WeakThis, RE, P]()
			{ if (WeakThis.IsValid()) WeakThis->OnFailure.Broadcast(RE, P); });
			return;
		}
		State->TotalBytes = Bytes.Num();
		FOpenSSLCryptoResult R = MW_DoEncrypt_RawKey(Bytes, *KeyPtr, State);
		MW_DispatchFileResult(WeakThis, OutPath, MoveTemp(R), State);
	});
}


// Activate() — MW Decrypt File RawKey


UAsyncMW_DecryptFile_RawKey* UAsyncMW_DecryptFile_RawKey::MW_DecryptFile_AES256GCM_RawKey(
	const FString& In, const FString& Out, const TArray<uint8>& Key, EOpenSSLWorkerMode Mode)
{
	auto* Node = NewObject<UAsyncMW_DecryptFile_RawKey>();
	Node->InputFilePath  = In;
	Node->OutputFilePath = Out;
	Node->RawKey32       = Key;
	Node->WorkerMode     = Mode;
	return Node;
}

void UAsyncMW_DecryptFile_RawKey::Activate()
{
	auto State = MakeShared<FMWSharedState>();
	State->NumWorkers   = GetNumWorkers(WorkerMode);
	State->LogicalCores = FPlatformMisc::NumberOfCoresIncludingHyperthreads();
	State->StartTimeSec = FPlatformTime::Seconds();

	FString InPath  = InputFilePath;
	FString OutPath = OutputFilePath;
	TSharedPtr<TArray<uint8>> KeyPtr = MakeShared<TArray<uint8>>(RawKey32);

	TWeakObjectPtr<UAsyncMW_DecryptFile_RawKey> WeakThis(this);

	MW_START_POLLER_FILE(State, WeakThis)

	Async(EAsyncExecution::Thread,
		[State, WeakThis, InPath, OutPath, KeyPtr]()
	{
		TArray<uint8> Bytes; FString RE;
		if (!MW_ReadFile(InPath, Bytes, RE))
		{
			State->bPollerStop = true;
			FOpenSSLCryptoProgress P = BuildProgress(State);
			AsyncTask(ENamedThreads::GameThread, [WeakThis, RE, P]()
			{ if (WeakThis.IsValid()) WeakThis->OnFailure.Broadcast(RE, P); });
			return;
		}
		State->TotalBytes = Bytes.Num();
		FOpenSSLCryptoResult R = MW_DoDecrypt_RawKey(Bytes, *KeyPtr, State);
		MW_DispatchFileResult(WeakThis, OutPath, MoveTemp(R), State);
	});
}
