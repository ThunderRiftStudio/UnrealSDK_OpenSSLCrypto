// OpenSSLCryptoAsyncTasks.cpp

#include "OpenSSLCryptoAsyncTasks.h"
#include "Async/Async.h"
#include "HAL/PlatformTime.h"

DEFINE_LOG_CATEGORY_STATIC(LogOpenSSLCryptoAsync, Log, All);

// Convertit un nombre d'octets en Mo, uniquement pour les logs.
static double AsyncBytesToMB(int64 Bytes)
{
	return (double)Bytes / 1048576.0;
}

// Ce qui s'execute sur le game thread dans ces noeuds :
//   1. La fabrique (AsyncXxx) : une copie du buffer d'entree. Blueprint passe une
//      reference valide seulement pendant l'appel, donc cette copie est obligatoire.
//   2. Activate() : le buffer est DEPLACE (MoveTemp) vers un TSharedPtr, aucune copie.
//      Avant, il y avait 2 copies de plus ici (copie locale + capture du lambda).
//   3. Le callback final : Broadcast() vers Blueprint. Un delegate dynamique copie
//      les parametres, donc le tableau resultat est copie une fois ici (inevitable).
// Le chiffrement lui-meme tourne sur un thread OS dedie (Async + EAsyncExecution::Thread).
// Les logs LogOpenSSLCryptoAsync donnent le temps passe sur le game thread a chaque etape.

// UAsyncEncryptAES256GCM

UAsyncEncryptAES256GCM* UAsyncEncryptAES256GCM::AsyncEncryptAES256GCM(
	const TArray<uint8>& InPlaintext,
	const FString&       InPassword,
	int32                InIterations)
{
	UAsyncEncryptAES256GCM* Node = NewObject<UAsyncEncryptAES256GCM>();

	// Copie unique du buffer d'entree (game thread).
	const double T0 = FPlatformTime::Seconds();
	Node->Plaintext = InPlaintext;
	const double CopyMs = (FPlatformTime::Seconds() - T0) * 1000.0;

	Node->Password   = InPassword;
	Node->Iterations = InIterations;

	UE_LOG(LogOpenSSLCryptoAsync, Log,
		TEXT("Encrypt Password : copie entree %.2f Mo sur le game thread = %.2f ms"),
		AsyncBytesToMB(InPlaintext.Num()), CopyMs);
	return Node;
}

void UAsyncEncryptAES256GCM::Activate()
{
	// Deplace le buffer du noeud vers un TSharedPtr (zero copie). Le TSharedPtr est
	// copiable, donc utilisable dans une lambda sans dupliquer les donnees.
	TSharedPtr<TArray<uint8>> PlainPtr = MakeShared<TArray<uint8>>(MoveTemp(Plaintext));
	FString LocalPassword   = Password;
	int32   LocalIterations = Iterations;

	TWeakObjectPtr<UAsyncEncryptAES256GCM> WeakThis(this);

	Async(EAsyncExecution::Thread,
		[WeakThis, PlainPtr, LocalPassword, LocalIterations]() mutable
	{
		const double T0 = FPlatformTime::Seconds();
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(
				*PlainPtr, LocalPassword, LocalIterations);
		const double CryptoMs = (FPlatformTime::Seconds() - T0) * 1000.0;

		// Libere le buffer d'entree des que le chiffrement est fini.
		PlainPtr.Reset();

		UE_LOG(LogOpenSSLCryptoAsync, Log,
			TEXT("Encrypt Password : chiffrement (thread dedie) = %.2f ms"), CryptoMs);

		// Le resultat est deplace dans un TSharedPtr pour ne pas etre copie
		// quand la lambda du game thread est creee.
		const bool    bOk = Result.bSuccess;
		const FString Err = Result.ErrorMessage;
		TSharedPtr<TArray<uint8>> DataPtr = MakeShared<TArray<uint8>>(MoveTemp(Result.Data));

		AsyncTask(ENamedThreads::GameThread, [WeakThis, bOk, Err, DataPtr]()
		{
			if (!WeakThis.IsValid()) { return; }

			const double T1 = FPlatformTime::Seconds();
			if (bOk)
				WeakThis->OnSuccess.Broadcast(*DataPtr, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Err);

			UE_LOG(LogOpenSSLCryptoAsync, Log,
				TEXT("Encrypt Password : Broadcast sur le game thread = %.2f ms"),
				(FPlatformTime::Seconds() - T1) * 1000.0);
		});
	});
}

// UAsyncDecryptAES256GCM

UAsyncDecryptAES256GCM* UAsyncDecryptAES256GCM::AsyncDecryptAES256GCM(
	const TArray<uint8>& InEncryptedPayload,
	const FString&       InPassword,
	int32                InIterations)
{
	UAsyncDecryptAES256GCM* Node = NewObject<UAsyncDecryptAES256GCM>();

	const double T0 = FPlatformTime::Seconds();
	Node->EncryptedPayload = InEncryptedPayload;
	const double CopyMs = (FPlatformTime::Seconds() - T0) * 1000.0;

	Node->Password   = InPassword;
	Node->Iterations = InIterations;

	UE_LOG(LogOpenSSLCryptoAsync, Log,
		TEXT("Decrypt Password : copie entree %.2f Mo sur le game thread = %.2f ms"),
		AsyncBytesToMB(InEncryptedPayload.Num()), CopyMs);
	return Node;
}

void UAsyncDecryptAES256GCM::Activate()
{
	TSharedPtr<TArray<uint8>> PayloadPtr = MakeShared<TArray<uint8>>(MoveTemp(EncryptedPayload));
	FString LocalPassword   = Password;
	int32   LocalIterations = Iterations;

	TWeakObjectPtr<UAsyncDecryptAES256GCM> WeakThis(this);

	Async(EAsyncExecution::Thread,
		[WeakThis, PayloadPtr, LocalPassword, LocalIterations]() mutable
	{
		const double T0 = FPlatformTime::Seconds();
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(
				*PayloadPtr, LocalPassword, LocalIterations);
		const double CryptoMs = (FPlatformTime::Seconds() - T0) * 1000.0;

		PayloadPtr.Reset();

		UE_LOG(LogOpenSSLCryptoAsync, Log,
			TEXT("Decrypt Password : dechiffrement (thread dedie) = %.2f ms"), CryptoMs);

		const bool    bOk = Result.bSuccess;
		const FString Err = Result.ErrorMessage;
		TSharedPtr<TArray<uint8>> DataPtr = MakeShared<TArray<uint8>>(MoveTemp(Result.Data));

		AsyncTask(ENamedThreads::GameThread, [WeakThis, bOk, Err, DataPtr]()
		{
			if (!WeakThis.IsValid()) { return; }

			const double T1 = FPlatformTime::Seconds();
			if (bOk)
				WeakThis->OnSuccess.Broadcast(*DataPtr, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Err);

			UE_LOG(LogOpenSSLCryptoAsync, Log,
				TEXT("Decrypt Password : Broadcast sur le game thread = %.2f ms"),
				(FPlatformTime::Seconds() - T1) * 1000.0);
		});
	});
}

// UAsyncEncryptAES256GCM_RawKey

UAsyncEncryptAES256GCM_RawKey* UAsyncEncryptAES256GCM_RawKey::AsyncEncryptAES256GCM_RawKey(
	const TArray<uint8>& InPlaintext,
	const TArray<uint8>& InRawKey32)
{
	UAsyncEncryptAES256GCM_RawKey* Node = NewObject<UAsyncEncryptAES256GCM_RawKey>();

	const double T0 = FPlatformTime::Seconds();
	Node->Plaintext = InPlaintext;
	const double CopyMs = (FPlatformTime::Seconds() - T0) * 1000.0;

	Node->RawKey32 = InRawKey32;

	UE_LOG(LogOpenSSLCryptoAsync, Log,
		TEXT("Encrypt RawKey : copie entree %.2f Mo sur le game thread = %.2f ms"),
		AsyncBytesToMB(InPlaintext.Num()), CopyMs);
	return Node;
}

void UAsyncEncryptAES256GCM_RawKey::Activate()
{
	TSharedPtr<TArray<uint8>> PlainPtr = MakeShared<TArray<uint8>>(MoveTemp(Plaintext));
	// La cle fait 32 octets, la copier est negligeable.
	TArray<uint8> LocalKey = RawKey32;

	TWeakObjectPtr<UAsyncEncryptAES256GCM_RawKey> WeakThis(this);

	Async(EAsyncExecution::Thread,
		[WeakThis, PlainPtr, LocalKey]() mutable
	{
		const double T0 = FPlatformTime::Seconds();
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM_RawKey(*PlainPtr, LocalKey);
		const double CryptoMs = (FPlatformTime::Seconds() - T0) * 1000.0;

		PlainPtr.Reset();

		UE_LOG(LogOpenSSLCryptoAsync, Log,
			TEXT("Encrypt RawKey : chiffrement (thread dedie) = %.2f ms"), CryptoMs);

		const bool    bOk = Result.bSuccess;
		const FString Err = Result.ErrorMessage;
		TSharedPtr<TArray<uint8>> DataPtr = MakeShared<TArray<uint8>>(MoveTemp(Result.Data));

		AsyncTask(ENamedThreads::GameThread, [WeakThis, bOk, Err, DataPtr]()
		{
			if (!WeakThis.IsValid()) { return; }

			const double T1 = FPlatformTime::Seconds();
			if (bOk)
				WeakThis->OnSuccess.Broadcast(*DataPtr, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Err);

			UE_LOG(LogOpenSSLCryptoAsync, Log,
				TEXT("Encrypt RawKey : Broadcast sur le game thread = %.2f ms"),
				(FPlatformTime::Seconds() - T1) * 1000.0);
		});
	});
}

// UAsyncDecryptAES256GCM_RawKey

UAsyncDecryptAES256GCM_RawKey* UAsyncDecryptAES256GCM_RawKey::AsyncDecryptAES256GCM_RawKey(
	const TArray<uint8>& InEncryptedPayload,
	const TArray<uint8>& InRawKey32)
{
	UAsyncDecryptAES256GCM_RawKey* Node = NewObject<UAsyncDecryptAES256GCM_RawKey>();

	const double T0 = FPlatformTime::Seconds();
	Node->EncryptedPayload = InEncryptedPayload;
	const double CopyMs = (FPlatformTime::Seconds() - T0) * 1000.0;

	Node->RawKey32 = InRawKey32;

	UE_LOG(LogOpenSSLCryptoAsync, Log,
		TEXT("Decrypt RawKey : copie entree %.2f Mo sur le game thread = %.2f ms"),
		AsyncBytesToMB(InEncryptedPayload.Num()), CopyMs);
	return Node;
}

void UAsyncDecryptAES256GCM_RawKey::Activate()
{
	TSharedPtr<TArray<uint8>> PayloadPtr = MakeShared<TArray<uint8>>(MoveTemp(EncryptedPayload));
	TArray<uint8> LocalKey = RawKey32;

	TWeakObjectPtr<UAsyncDecryptAES256GCM_RawKey> WeakThis(this);

	Async(EAsyncExecution::Thread,
		[WeakThis, PayloadPtr, LocalKey]() mutable
	{
		const double T0 = FPlatformTime::Seconds();
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM_RawKey(*PayloadPtr, LocalKey);
		const double CryptoMs = (FPlatformTime::Seconds() - T0) * 1000.0;

		PayloadPtr.Reset();

		UE_LOG(LogOpenSSLCryptoAsync, Log,
			TEXT("Decrypt RawKey : dechiffrement (thread dedie) = %.2f ms"), CryptoMs);

		const bool    bOk = Result.bSuccess;
		const FString Err = Result.ErrorMessage;
		TSharedPtr<TArray<uint8>> DataPtr = MakeShared<TArray<uint8>>(MoveTemp(Result.Data));

		AsyncTask(ENamedThreads::GameThread, [WeakThis, bOk, Err, DataPtr]()
		{
			if (!WeakThis.IsValid()) { return; }

			const double T1 = FPlatformTime::Seconds();
			if (bOk)
				WeakThis->OnSuccess.Broadcast(*DataPtr, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Err);

			UE_LOG(LogOpenSSLCryptoAsync, Log,
				TEXT("Decrypt RawKey : Broadcast sur le game thread = %.2f ms"),
				(FPlatformTime::Seconds() - T1) * 1000.0);
		});
	});
}
