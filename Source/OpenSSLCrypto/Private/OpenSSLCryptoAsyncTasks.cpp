// OpenSSLCryptoAsyncTasks.cpp

#include "OpenSSLCryptoAsyncTasks.h"
#include "Async/Async.h"


// UAsyncEncryptAES256GCM


UAsyncEncryptAES256GCM* UAsyncEncryptAES256GCM::AsyncEncryptAES256GCM(
	const TArray<uint8>& InPlaintext,
	const FString&       InPassword,
	int32                InIterations)
{
	UAsyncEncryptAES256GCM* Node = NewObject<UAsyncEncryptAES256GCM>();
	Node->Plaintext  = InPlaintext;
	Node->Password   = InPassword;
	Node->Iterations = InIterations;
	return Node;
}

void UAsyncEncryptAES256GCM::Activate()
{
	TArray<uint8> LocalPlaintext  = Plaintext;
	FString       LocalPassword   = Password;
	int32         LocalIterations = Iterations;

	TWeakObjectPtr<UAsyncEncryptAES256GCM> WeakThis(this);

	AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask,
		[WeakThis, LocalPlaintext, LocalPassword, LocalIterations]() mutable
	{
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(
				LocalPlaintext, LocalPassword, LocalIterations);

		AsyncTask(ENamedThreads::GameThread, [WeakThis, Result]()
		{
			if (!WeakThis.IsValid()) { return; }
			if (Result.bSuccess)
				WeakThis->OnSuccess.Broadcast(Result.Data, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Result.ErrorMessage);
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
	Node->EncryptedPayload = InEncryptedPayload;
	Node->Password         = InPassword;
	Node->Iterations       = InIterations;
	return Node;
}

void UAsyncDecryptAES256GCM::Activate()
{
	TArray<uint8> LocalPayload    = EncryptedPayload;
	FString       LocalPassword   = Password;
	int32         LocalIterations = Iterations;

	TWeakObjectPtr<UAsyncDecryptAES256GCM> WeakThis(this);

	AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask,
		[WeakThis, LocalPayload, LocalPassword, LocalIterations]() mutable
	{
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(
				LocalPayload, LocalPassword, LocalIterations);

		AsyncTask(ENamedThreads::GameThread, [WeakThis, Result]()
		{
			if (!WeakThis.IsValid()) { return; }
			if (Result.bSuccess)
				WeakThis->OnSuccess.Broadcast(Result.Data, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Result.ErrorMessage);
		});
	});
}


// UAsyncEncryptAES256GCM_RawKey


UAsyncEncryptAES256GCM_RawKey* UAsyncEncryptAES256GCM_RawKey::AsyncEncryptAES256GCM_RawKey(
	const TArray<uint8>& InPlaintext,
	const TArray<uint8>& InRawKey32)
{
	UAsyncEncryptAES256GCM_RawKey* Node = NewObject<UAsyncEncryptAES256GCM_RawKey>();
	Node->Plaintext = InPlaintext;
	Node->RawKey32  = InRawKey32;
	return Node;
}

void UAsyncEncryptAES256GCM_RawKey::Activate()
{
	TArray<uint8> LocalPlaintext = Plaintext;
	TArray<uint8> LocalKey       = RawKey32;

	TWeakObjectPtr<UAsyncEncryptAES256GCM_RawKey> WeakThis(this);

	AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask,
		[WeakThis, LocalPlaintext, LocalKey]() mutable
	{
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM_RawKey(LocalPlaintext, LocalKey);

		AsyncTask(ENamedThreads::GameThread, [WeakThis, Result]()
		{
			if (!WeakThis.IsValid()) { return; }
			if (Result.bSuccess)
				WeakThis->OnSuccess.Broadcast(Result.Data, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Result.ErrorMessage);
		});
	});
}


// UAsyncDecryptAES256GCM_RawKey


UAsyncDecryptAES256GCM_RawKey* UAsyncDecryptAES256GCM_RawKey::AsyncDecryptAES256GCM_RawKey(
	const TArray<uint8>& InEncryptedPayload,
	const TArray<uint8>& InRawKey32)
{
	UAsyncDecryptAES256GCM_RawKey* Node = NewObject<UAsyncDecryptAES256GCM_RawKey>();
	Node->EncryptedPayload = InEncryptedPayload;
	Node->RawKey32         = InRawKey32;
	return Node;
}

void UAsyncDecryptAES256GCM_RawKey::Activate()
{
	TArray<uint8> LocalPayload = EncryptedPayload;
	TArray<uint8> LocalKey     = RawKey32;

	TWeakObjectPtr<UAsyncDecryptAES256GCM_RawKey> WeakThis(this);

	AsyncTask(ENamedThreads::AnyBackgroundThreadNormalTask,
		[WeakThis, LocalPayload, LocalKey]() mutable
	{
		FOpenSSLCryptoResult Result =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM_RawKey(LocalPayload, LocalKey);

		AsyncTask(ENamedThreads::GameThread, [WeakThis, Result]()
		{
			if (!WeakThis.IsValid()) { return; }
			if (Result.bSuccess)
				WeakThis->OnSuccess.Broadcast(Result.Data, FString());
			else
				WeakThis->OnFailure.Broadcast(TArray<uint8>(), Result.ErrorMessage);
		});
	});
}
