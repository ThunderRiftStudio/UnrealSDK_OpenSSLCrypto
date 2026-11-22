#pragma once

/**
 * OpenSSLCryptoMultiWorker.h
 *
 * POURQUOI UN SEUL TYPE DE DELEGATE PAR NOEUD :
 *   UK2Node_AsyncAction (UE5) ne genere les output data pins que depuis les
 *   delegates qui partagent exactement les memes parametres. Si OnProgress,
 *   OnSuccess et OnFailure ont des signatures differentes, seuls les parametres
 *   communs apparaissent. Solution : un seul FOnMWBytesEvent pour les 3 events.
 *
 *   OnProgress -> Progress valide, Data vide, ErrorMessage vide
 *   OnSuccess  -> Data valide (bytes), Progress valide (final), ErrorMessage vide
 *   OnFailure  -> ErrorMessage valide, Progress valide (au moment erreur), Data vide
 *
 * FORMAT MULTI-WORKER (incompatible avec single-worker) :
 *   Password : [Magic"OSCMWP01"][SALT 16B][TotalSize 8B][NumChunks 4B][ChunkSize 8B]
 *              + par chunk : [IV 12B][TAG 16B][CIPHERTEXT]
 *   RawKey   : [Magic"OSCMWK01"][TotalSize 8B][NumChunks 4B][ChunkSize 8B]
 *              + par chunk : [IV 12B][TAG 16B][CIPHERTEXT]
 */

#include "CoreMinimal.h"
#include "Kismet/BlueprintAsyncActionBase.h"
#include "OpenSSLCryptoBPLibrary.h"
#include "OpenSSLCryptoTypes.h"
#include "OpenSSLCryptoMultiWorker.generated.h"


// Delegates unifies — UN SEUL TYPE par famille de noeuds
//
// FOnMWBytesEvent (noeuds Bytes) — 3 params toujours presents sur le noeud :
//   Data         = TArray<uint8> — bytes resultat   (valide sur OnSuccess)
//   ErrorMessage = FString       — raison erreur    (valide sur OnFailure)
//   Progress     = struct        — avancement       (valide sur les 3 events)
//
// FOnMWFileEvent (noeuds File) — 2 params (pas de Data, ecrit sur disque) :
//   ErrorMessage = FString       — raison erreur    (valide sur OnFailure)
//   Progress     = struct        — avancement       (valide sur les 3 events)


DECLARE_DYNAMIC_MULTICAST_DELEGATE_ThreeParams(
	FOnMWBytesEvent,
	const TArray<uint8>&,          Data,
	const FString&,                ErrorMessage,
	const FOpenSSLCryptoProgress&, Progress);

DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(
	FOnMWFileEvent,
	const FString&,                ErrorMessage,
	const FOpenSSLCryptoProgress&, Progress);


// MW Encrypt Bytes — Password


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_EncryptBytes_Password : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	/** OnProgress : Data=vide | ErrorMessage=vide | Progress=etat courant */
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnProgress;
	/** OnSuccess  : Data=payload chiffre | ErrorMessage=vide | Progress=final */
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnSuccess;
	/** OnFailure  : Data=vide | ErrorMessage=raison | Progress=etat au moment erreur */
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Encrypt Bytes AES-256-GCM (Password)",
			Keywords = "encrypt bytes aes gcm multiworker parallel password"))
	static UAsyncMW_EncryptBytes_Password* MW_EncryptBytes_AES256GCM(
		const TArray<uint8>&  Plaintext,
		const FString&        Password,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High,
		int32                 Iterations = 100000);

	virtual void Activate() override;
private:
	TArray<uint8> Plaintext; FString Password;
	EOpenSSLWorkerMode WorkerMode; int32 Iterations;
};


// MW Decrypt Bytes — Password


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_DecryptBytes_Password : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	/** OnProgress : Data=vide | ErrorMessage=vide | Progress=etat courant */
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnProgress;
	/** OnSuccess  : Data=plaintext dechiffre | ErrorMessage=vide | Progress=final */
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnSuccess;
	/** OnFailure  : Data=vide | ErrorMessage=raison | Progress=etat erreur */
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Decrypt Bytes AES-256-GCM (Password)",
			Keywords = "decrypt bytes aes gcm multiworker parallel password"))
	static UAsyncMW_DecryptBytes_Password* MW_DecryptBytes_AES256GCM(
		const TArray<uint8>&  EncryptedPayload,
		const FString&        Password,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High,
		int32                 Iterations = 100000);

	virtual void Activate() override;
private:
	TArray<uint8> EncryptedPayload; FString Password;
	EOpenSSLWorkerMode WorkerMode; int32 Iterations;
};


// MW Encrypt Bytes — Raw Key


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_EncryptBytes_RawKey : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnProgress;
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnSuccess;
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Encrypt Bytes AES-256-GCM (Raw Key)",
			Keywords = "encrypt bytes aes gcm multiworker parallel raw key"))
	static UAsyncMW_EncryptBytes_RawKey* MW_EncryptBytes_AES256GCM_RawKey(
		const TArray<uint8>&  Plaintext,
		const TArray<uint8>&  RawKey32,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High);

	virtual void Activate() override;
private:
	TArray<uint8> Plaintext; TArray<uint8> RawKey32;
	EOpenSSLWorkerMode WorkerMode;
};


// MW Decrypt Bytes — Raw Key


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_DecryptBytes_RawKey : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnProgress;
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnSuccess;
	UPROPERTY(BlueprintAssignable) FOnMWBytesEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Decrypt Bytes AES-256-GCM (Raw Key)",
			Keywords = "decrypt bytes aes gcm multiworker parallel raw key"))
	static UAsyncMW_DecryptBytes_RawKey* MW_DecryptBytes_AES256GCM_RawKey(
		const TArray<uint8>&  EncryptedPayload,
		const TArray<uint8>&  RawKey32,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High);

	virtual void Activate() override;
private:
	TArray<uint8> EncryptedPayload; TArray<uint8> RawKey32;
	EOpenSSLWorkerMode WorkerMode;
};


// MW Encrypt File — Password


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_EncryptFile_Password : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	/** OnProgress : ErrorMessage=vide | Progress=etat courant */
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnProgress;
	/** OnSuccess  : ErrorMessage=vide | Progress=final */
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnSuccess;
	/** OnFailure  : ErrorMessage=raison | Progress=etat erreur */
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker|File",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Encrypt File AES-256-GCM (Password)",
			Keywords = "encrypt file aes gcm multiworker parallel password"))
	static UAsyncMW_EncryptFile_Password* MW_EncryptFile_AES256GCM(
		const FString&        InputFilePath,
		const FString&        OutputFilePath,
		const FString&        Password,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High,
		int32                 Iterations = 100000);

	virtual void Activate() override;
private:
	FString InputFilePath, OutputFilePath, Password;
	EOpenSSLWorkerMode WorkerMode; int32 Iterations;
};


// MW Decrypt File — Password


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_DecryptFile_Password : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnProgress;
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnSuccess;
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker|File",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Decrypt File AES-256-GCM (Password)",
			Keywords = "decrypt file aes gcm multiworker parallel password"))
	static UAsyncMW_DecryptFile_Password* MW_DecryptFile_AES256GCM(
		const FString&        InputFilePath,
		const FString&        OutputFilePath,
		const FString&        Password,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High,
		int32                 Iterations = 100000);

	virtual void Activate() override;
private:
	FString InputFilePath, OutputFilePath, Password;
	EOpenSSLWorkerMode WorkerMode; int32 Iterations;
};


// MW Encrypt File — Raw Key


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_EncryptFile_RawKey : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnProgress;
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnSuccess;
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker|File",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Encrypt File AES-256-GCM (Raw Key)",
			Keywords = "encrypt file aes gcm multiworker parallel raw key"))
	static UAsyncMW_EncryptFile_RawKey* MW_EncryptFile_AES256GCM_RawKey(
		const FString&        InputFilePath,
		const FString&        OutputFilePath,
		const TArray<uint8>&  RawKey32,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High);

	virtual void Activate() override;
private:
	FString InputFilePath, OutputFilePath;
	TArray<uint8> RawKey32; EOpenSSLWorkerMode WorkerMode;
};


// MW Decrypt File — Raw Key


UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncMW_DecryptFile_RawKey : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()
public:

	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnProgress;
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnSuccess;
	UPROPERTY(BlueprintAssignable) FOnMWFileEvent OnFailure;

	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|MultiWorker|File",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "MW Decrypt File AES-256-GCM (Raw Key)",
			Keywords = "decrypt file aes gcm multiworker parallel raw key"))
	static UAsyncMW_DecryptFile_RawKey* MW_DecryptFile_AES256GCM_RawKey(
		const FString&        InputFilePath,
		const FString&        OutputFilePath,
		const TArray<uint8>&  RawKey32,
		EOpenSSLWorkerMode    WorkerMode = EOpenSSLWorkerMode::High);

	virtual void Activate() override;
private:
	FString InputFilePath, OutputFilePath;
	TArray<uint8> RawKey32; EOpenSSLWorkerMode WorkerMode;
};
