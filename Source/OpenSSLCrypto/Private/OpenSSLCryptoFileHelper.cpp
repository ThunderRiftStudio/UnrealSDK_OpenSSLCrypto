// OpenSSLCryptoFileHelper.cpp

#include "OpenSSLCryptoFileHelper.h"
#include "Misc/FileHelper.h"
#include "Misc/Paths.h"
#include "HAL/PlatformFileManager.h"

// ---------------------------------------------------------------------------
// Helpers internes
// ---------------------------------------------------------------------------

static FOpenSSLCryptoResult FileH_Err(const FString& Msg)
{
	FOpenSSLCryptoResult R; R.bSuccess = false; R.ErrorMessage = Msg; return R;
}
static FOpenSSLCryptoResult FileH_ErrLit(const TCHAR* Msg)
{
	FOpenSSLCryptoResult R; R.bSuccess = false; R.ErrorMessage = FString(Msg); return R;
}
static FOpenSSLCryptoResult FileH_Ok()
{
	FOpenSSLCryptoResult R; R.bSuccess = true; return R;
}
static FOpenSSLCryptoResult FileH_OkData(TArray<uint8>&& Data)
{
	FOpenSSLCryptoResult R; R.bSuccess = true; R.Data = MoveTemp(Data); return R;
}

static bool FileH_Read(const FString& Path, TArray<uint8>& Out, FString& Err)
{
	IPlatformFile& PF = FPlatformFileManager::Get().GetPlatformFile();
	if (!PF.FileExists(*Path)) { Err = FString::Printf(TEXT("Fichier introuvable : %s"), *Path); return false; }
	if (!FFileHelper::LoadFileToArray(Out, *Path)) { Err = FString::Printf(TEXT("Impossible de lire : %s"), *Path); return false; }
	return true;
}

static bool FileH_Write(const FString& Path, const TArray<uint8>& Data, FString& Err)
{
	const FString Dir = FPaths::GetPath(Path);
	if (!Dir.IsEmpty())
	{
		IPlatformFile& PF = FPlatformFileManager::Get().GetPlatformFile();
		if (!PF.DirectoryExists(*Dir) && !PF.CreateDirectoryTree(*Dir))
		{
			Err = FString::Printf(TEXT("Impossible de creer le dossier : %s"), *Dir); return false;
		}
	}
	if (!FFileHelper::SaveArrayToFile(Data, *Path)) { Err = FString::Printf(TEXT("Impossible d'ecrire : %s"), *Path); return false; }
	return true;
}

// Convertit une FString en octets ASCII (1 char = 1 octet, troncature 8 bits)
static TArray<uint8> FileH_StringToBytes(const FString& Str)
{
	TArray<uint8> B; B.Reserve(Str.Len());
	for (int32 i = 0; i < Str.Len(); i++) { B.Add(static_cast<uint8>(Str[i] & 0xFF)); }
	return B;
}

// Lit seulement les N premiers octets d'un fichier
static bool FileH_ReadHeader(const FString& Path, int32 N, TArray<uint8>& Out)
{
	IPlatformFile& PF = FPlatformFileManager::Get().GetPlatformFile();
	if (!PF.FileExists(*Path)) { return false; }
	IFileHandle* H = PF.OpenRead(*Path);
	if (!H) { return false; }
	Out.SetNumUninitialized(N);
	const bool bOK = H->Read(Out.GetData(), N);
	delete H;
	if (!bOK) { Out.Empty(); }
	return bOK;
}

// Shared : check magic dans un tableau d'octets
static bool FileH_CheckMagicInBytes(const TArray<uint8>& InBytes, const TArray<uint8>& Magic, FString& Err)
{
	if (InBytes.Num() < Magic.Num())
	{
		Err = FString::Printf(TEXT("Donnees trop courtes (%d octets) pour contenir le magic (%d octets)."), InBytes.Num(), Magic.Num());
		return false;
	}
	if (FMemory::Memcmp(InBytes.GetData(), Magic.GetData(), Magic.Num()) != 0)
	{
		Err = TEXT("Magic invalide : les donnees ne commencent pas par la signature attendue.");
		return false;
	}
	return true;
}

// Shared : strip magic depuis un tableau d'octets (retourne les octets apres le magic)
static TArray<uint8> FileH_StripMagicFromBytes(const TArray<uint8>& InBytes, int32 MagicLen)
{
	TArray<uint8> Out;
	const int32 Remaining = InBytes.Num() - MagicLen;
	if (Remaining > 0) { Out.Append(InBytes.GetData() + MagicLen, Remaining); }
	return Out;
}

// ---------------------------------------------------------------------------
// Shared implementations all-in-one
// ---------------------------------------------------------------------------

static FOpenSSLCryptoResult FileH_EncryptWithMagic_Password(
	const FString& In, const FString& Out,
	const FString& Password, int32 Iterations,
	const TArray<uint8>& Magic)
{
	if (In.IsEmpty())      return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (Out.IsEmpty())     return FileH_ErrLit(TEXT("OutputFilePath est vide."));
	if (Magic.Num() == 0)  return FileH_ErrLit(TEXT("Magic est vide."));

	TArray<uint8> Plaintext; FString RE;
	if (!FileH_Read(In, Plaintext, RE)) return FileH_Err(RE);

	FOpenSSLCryptoResult Enc = UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, Password, Iterations);
	if (!Enc.bSuccess) return Enc;

	TArray<uint8> Output; Output.Reserve(Magic.Num() + Enc.Data.Num());
	Output.Append(Magic); Output.Append(Enc.Data);

	FString WE;
	if (!FileH_Write(Out, Output, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

static FOpenSSLCryptoResult FileH_DecryptWithMagic_Password(
	const FString& In, const FString& Out,
	const FString& Password, int32 Iterations,
	const TArray<uint8>& Magic)
{
	if (In.IsEmpty())      return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (Out.IsEmpty())     return FileH_ErrLit(TEXT("OutputFilePath est vide."));
	if (Magic.Num() == 0)  return FileH_ErrLit(TEXT("Magic est vide."));

	TArray<uint8> RawFile; FString RE;
	if (!FileH_Read(In, RawFile, RE)) return FileH_Err(RE);

	FString ME;
	if (!FileH_CheckMagicInBytes(RawFile, Magic, ME)) return FileH_Err(ME);

	TArray<uint8> Payload; Payload.Append(RawFile.GetData() + Magic.Num(), RawFile.Num() - Magic.Num());

	FOpenSSLCryptoResult Dec = UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Payload, Password, Iterations);
	if (!Dec.bSuccess) return Dec;

	FString WE;
	if (!FileH_Write(Out, Dec.Data, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

static FOpenSSLCryptoResult FileH_EncryptWithMagic_RawKey(
	const FString& In, const FString& Out,
	const TArray<uint8>& Key, const TArray<uint8>& Magic)
{
	if (In.IsEmpty())      return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (Out.IsEmpty())     return FileH_ErrLit(TEXT("OutputFilePath est vide."));
	if (Magic.Num() == 0)  return FileH_ErrLit(TEXT("Magic est vide."));

	TArray<uint8> Plaintext; FString RE;
	if (!FileH_Read(In, Plaintext, RE)) return FileH_Err(RE);

	FOpenSSLCryptoResult Enc = UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM_RawKey(Plaintext, Key);
	if (!Enc.bSuccess) return Enc;

	TArray<uint8> Output; Output.Reserve(Magic.Num() + Enc.Data.Num());
	Output.Append(Magic); Output.Append(Enc.Data);

	FString WE;
	if (!FileH_Write(Out, Output, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

static FOpenSSLCryptoResult FileH_DecryptWithMagic_RawKey(
	const FString& In, const FString& Out,
	const TArray<uint8>& Key, const TArray<uint8>& Magic)
{
	if (In.IsEmpty())      return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (Out.IsEmpty())     return FileH_ErrLit(TEXT("OutputFilePath est vide."));
	if (Magic.Num() == 0)  return FileH_ErrLit(TEXT("Magic est vide."));

	TArray<uint8> RawFile; FString RE;
	if (!FileH_Read(In, RawFile, RE)) return FileH_Err(RE);

	FString ME;
	if (!FileH_CheckMagicInBytes(RawFile, Magic, ME)) return FileH_Err(ME);

	TArray<uint8> Payload; Payload.Append(RawFile.GetData() + Magic.Num(), RawFile.Num() - Magic.Num());

	FOpenSSLCryptoResult Dec = UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM_RawKey(Payload, Key);
	if (!Dec.bSuccess) return Dec;

	FString WE;
	if (!FileH_Write(Out, Dec.Data, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

// 1. CHIFFREMENT / DECHIFFREMENT FICHIER (sans magic)

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::EncryptFile_AES256GCM(
	const FString& InputFilePath, const FString& OutputFilePath,
	const FString& Password, int32 Iterations)
{
	if (InputFilePath.IsEmpty())  return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (OutputFilePath.IsEmpty()) return FileH_ErrLit(TEXT("OutputFilePath est vide."));

	TArray<uint8> Plaintext; FString RE;
	if (!FileH_Read(InputFilePath, Plaintext, RE)) return FileH_Err(RE);

	FOpenSSLCryptoResult Enc = UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, Password, Iterations);
	if (!Enc.bSuccess) return Enc;

	FString WE;
	if (!FileH_Write(OutputFilePath, Enc.Data, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::DecryptFile_AES256GCM(
	const FString& InputFilePath, const FString& OutputFilePath,
	const FString& Password, int32 Iterations)
{
	if (InputFilePath.IsEmpty())  return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (OutputFilePath.IsEmpty()) return FileH_ErrLit(TEXT("OutputFilePath est vide."));

	TArray<uint8> Encrypted; FString RE;
	if (!FileH_Read(InputFilePath, Encrypted, RE)) return FileH_Err(RE);

	FOpenSSLCryptoResult Dec = UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Encrypted, Password, Iterations);
	if (!Dec.bSuccess) return Dec;

	FString WE;
	if (!FileH_Write(OutputFilePath, Dec.Data, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::EncryptFile_AES256GCM_RawKey(
	const FString& InputFilePath, const FString& OutputFilePath,
	const TArray<uint8>& RawKey32)
{
	if (InputFilePath.IsEmpty())  return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (OutputFilePath.IsEmpty()) return FileH_ErrLit(TEXT("OutputFilePath est vide."));

	TArray<uint8> Plaintext; FString RE;
	if (!FileH_Read(InputFilePath, Plaintext, RE)) return FileH_Err(RE);

	FOpenSSLCryptoResult Enc = UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM_RawKey(Plaintext, RawKey32);
	if (!Enc.bSuccess) return Enc;

	FString WE;
	if (!FileH_Write(OutputFilePath, Enc.Data, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::DecryptFile_AES256GCM_RawKey(
	const FString& InputFilePath, const FString& OutputFilePath,
	const TArray<uint8>& RawKey32)
{
	if (InputFilePath.IsEmpty())  return FileH_ErrLit(TEXT("InputFilePath est vide."));
	if (OutputFilePath.IsEmpty()) return FileH_ErrLit(TEXT("OutputFilePath est vide."));

	TArray<uint8> Encrypted; FString RE;
	if (!FileH_Read(InputFilePath, Encrypted, RE)) return FileH_Err(RE);

	FOpenSSLCryptoResult Dec = UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM_RawKey(Encrypted, RawKey32);
	if (!Dec.bSuccess) return Dec;

	FString WE;
	if (!FileH_Write(OutputFilePath, Dec.Data, WE)) return FileH_Err(WE);
	return FileH_Ok();
}

// 2. MAGIC EN MEMOIRE (sur TArray<uint8>, zero fichier)

TArray<uint8> UOpenSSLCryptoFileHelper::PrependMagicStringToBytes(
	const TArray<uint8>& InBytes, const FString& MagicString)
{
	const TArray<uint8> Magic = FileH_StringToBytes(MagicString);
	TArray<uint8> Out; Out.Reserve(Magic.Num() + InBytes.Num());
	Out.Append(Magic); Out.Append(InBytes);
	return Out;
}

TArray<uint8> UOpenSSLCryptoFileHelper::PrependMagicBytesToBytes(
	const TArray<uint8>& InBytes, const TArray<uint8>& MagicBytes)
{
	TArray<uint8> Out; Out.Reserve(MagicBytes.Num() + InBytes.Num());
	Out.Append(MagicBytes); Out.Append(InBytes);
	return Out;
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::StripAndCheckMagicStringFromBytes(
	const TArray<uint8>& InBytes, const FString& MagicString)
{
	const TArray<uint8> Magic = FileH_StringToBytes(MagicString);
	FString ME;
	if (!FileH_CheckMagicInBytes(InBytes, Magic, ME)) return FileH_Err(ME);
	TArray<uint8> Stripped = FileH_StripMagicFromBytes(InBytes, Magic.Num());
	return FileH_OkData(MoveTemp(Stripped));
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::StripAndCheckMagicBytesFromBytes(
	const TArray<uint8>& InBytes, const TArray<uint8>& MagicBytes)
{
	FString ME;
	if (!FileH_CheckMagicInBytes(InBytes, MagicBytes, ME)) return FileH_Err(ME);
	TArray<uint8> Stripped = FileH_StripMagicFromBytes(InBytes, MagicBytes.Num());
	return FileH_OkData(MoveTemp(Stripped));
}

bool UOpenSSLCryptoFileHelper::BytesHaveMagicString(
	const TArray<uint8>& InBytes, const FString& MagicString)
{
	const TArray<uint8> Magic = FileH_StringToBytes(MagicString);
	if (InBytes.Num() < Magic.Num()) return false;
	return FMemory::Memcmp(InBytes.GetData(), Magic.GetData(), Magic.Num()) == 0;
}

bool UOpenSSLCryptoFileHelper::BytesHaveMagicBytes(
	const TArray<uint8>& InBytes, const TArray<uint8>& MagicBytes)
{
	if (InBytes.Num() < MagicBytes.Num()) return false;
	return FMemory::Memcmp(InBytes.GetData(), MagicBytes.GetData(), MagicBytes.Num()) == 0;
}

TArray<uint8> UOpenSSLCryptoFileHelper::MakeMagicBytesFromString(const FString& AsciiString)
{
	return FileH_StringToBytes(AsciiString);
}

// 3. ALL-IN-ONE (1 read + 1 write disque, zero fichier temporaire)

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::EncryptFileWithMagicString_AES256GCM(
	const FString& InputFilePath, const FString& OutputFilePath,
	const FString& Password, const FString& MagicString, int32 Iterations)
{
	return FileH_EncryptWithMagic_Password(InputFilePath, OutputFilePath, Password, Iterations, FileH_StringToBytes(MagicString));
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::DecryptFileWithMagicString_AES256GCM(
	const FString& InputFilePath, const FString& OutputFilePath,
	const FString& Password, const FString& MagicString, int32 Iterations)
{
	return FileH_DecryptWithMagic_Password(InputFilePath, OutputFilePath, Password, Iterations, FileH_StringToBytes(MagicString));
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::EncryptFileWithMagicString_AES256GCM_RawKey(
	const FString& InputFilePath, const FString& OutputFilePath,
	const TArray<uint8>& RawKey32, const FString& MagicString)
{
	return FileH_EncryptWithMagic_RawKey(InputFilePath, OutputFilePath, RawKey32, FileH_StringToBytes(MagicString));
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::DecryptFileWithMagicString_AES256GCM_RawKey(
	const FString& InputFilePath, const FString& OutputFilePath,
	const TArray<uint8>& RawKey32, const FString& MagicString)
{
	return FileH_DecryptWithMagic_RawKey(InputFilePath, OutputFilePath, RawKey32, FileH_StringToBytes(MagicString));
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::EncryptFileWithMagicBytes_AES256GCM(
	const FString& InputFilePath, const FString& OutputFilePath,
	const FString& Password, const TArray<uint8>& MagicBytes, int32 Iterations)
{
	return FileH_EncryptWithMagic_Password(InputFilePath, OutputFilePath, Password, Iterations, MagicBytes);
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::DecryptFileWithMagicBytes_AES256GCM(
	const FString& InputFilePath, const FString& OutputFilePath,
	const FString& Password, const TArray<uint8>& MagicBytes, int32 Iterations)
{
	return FileH_DecryptWithMagic_Password(InputFilePath, OutputFilePath, Password, Iterations, MagicBytes);
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::EncryptFileWithMagicBytes_AES256GCM_RawKey(
	const FString& InputFilePath, const FString& OutputFilePath,
	const TArray<uint8>& RawKey32, const TArray<uint8>& MagicBytes)
{
	return FileH_EncryptWithMagic_RawKey(InputFilePath, OutputFilePath, RawKey32, MagicBytes);
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::DecryptFileWithMagicBytes_AES256GCM_RawKey(
	const FString& InputFilePath, const FString& OutputFilePath,
	const TArray<uint8>& RawKey32, const TArray<uint8>& MagicBytes)
{
	return FileH_DecryptWithMagic_RawKey(InputFilePath, OutputFilePath, RawKey32, MagicBytes);
}

// UTILITAIRES FICHIER

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::ReadFileToBytes(const FString& FilePath)
{
	if (FilePath.IsEmpty()) return FileH_ErrLit(TEXT("FilePath est vide."));
	TArray<uint8> Bytes; FString Err;
	if (!FileH_Read(FilePath, Bytes, Err)) return FileH_Err(Err);
	return FileH_OkData(MoveTemp(Bytes));
}

FOpenSSLCryptoResult UOpenSSLCryptoFileHelper::WriteBytesToFile(
	const FString& FilePath, const TArray<uint8>& Data)
{
	if (FilePath.IsEmpty()) return FileH_ErrLit(TEXT("FilePath est vide."));
	FString Err;
	if (!FileH_Write(FilePath, Data, Err)) return FileH_Err(Err);
	return FileH_Ok();
}

bool UOpenSSLCryptoFileHelper::FileHasMagicString(
	const FString& FilePath, const FString& MagicString)
{
	const TArray<uint8> Magic = FileH_StringToBytes(MagicString);
	if (FilePath.IsEmpty() || Magic.Num() == 0) return false;
	TArray<uint8> Header;
	if (!FileH_ReadHeader(FilePath, Magic.Num(), Header)) return false;
	if (Header.Num() < Magic.Num()) return false;
	return FMemory::Memcmp(Header.GetData(), Magic.GetData(), Magic.Num()) == 0;
}

bool UOpenSSLCryptoFileHelper::FileHasMagicBytes(
	const FString& FilePath, const TArray<uint8>& MagicBytes)
{
	if (FilePath.IsEmpty() || MagicBytes.Num() == 0) return false;
	TArray<uint8> Header;
	if (!FileH_ReadHeader(FilePath, MagicBytes.Num(), Header)) return false;
	if (Header.Num() < MagicBytes.Num()) return false;
	return FMemory::Memcmp(Header.GetData(), MagicBytes.GetData(), MagicBytes.Num()) == 0;
}
