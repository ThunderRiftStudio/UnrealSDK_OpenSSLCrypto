#pragma once

/**
 * OpenSSLCryptoAsyncTasks.h
 *
 * Tâches asynchrones Blueprint pour le chiffrement/déchiffrement AES-256-GCM
 * Permet de ne pas bloquer le Game Thread pour les gros volumes de données
 *
 * Usage Blueprint :
 *   [Async Encrypt Bytes AES-256-GCM] → OnSuccess(Result) / OnFailure(ErrorMsg)
 */

#include "CoreMinimal.h"
#include "Kismet/BlueprintAsyncActionBase.h"
#include "OpenSSLCryptoBPLibrary.h"
#include "OpenSSLCryptoAsyncTasks.generated.h"

// ── Delegate de résultat 

DECLARE_DYNAMIC_MULTICAST_DELEGATE_TwoParams(
	FOnCryptoComplete,
	const TArray<uint8>&, Data,
	const FString&,        ErrorMessage);

// ── Encrypt async (mot de passe) 

/**
 * Chiffre un tableau d'octets de manière asynchrone (thread pool).
 * Ne bloque pas le Game Thread.
 */
UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncEncryptAES256GCM : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()

public:

	/** Appelé quand le chiffrement est terminé avec succès. Data = payload chiffré. */
	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnSuccess;

	/** Appelé si le chiffrement a échoué. Data = vide, ErrorMessage = raison. */
	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnFailure;

	/**
	 * Lance un chiffrement AES-256-GCM asynchrone avec dérivation PBKDF2.
	 *
	 * @param Plaintext   Données à chiffrer.
	 * @param Password    Mot de passe.
	 * @param Iterations  Itérations PBKDF2 (défaut : 100000).
	 */
	UFUNCTION(BlueprintCallable,
		Category = "OpenSSL Crypto|Async",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "Async AES-256-GCM Encrypt (Password)",
			Keywords = "encrypt aes gcm async openssl"))
	static UAsyncEncryptAES256GCM* AsyncEncryptAES256GCM(
		const TArray<uint8>& Plaintext,
		const FString&       Password,
		int32                Iterations = 100000);

	virtual void Activate() override;

private:
	TArray<uint8> Plaintext;
	FString       Password;
	int32         Iterations = 100000;
};

// ── Decrypt async (mot de passe) 

/**
 * Déchiffre un payload AES-256-GCM de manière asynchrone (thread pool).
 */
UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncDecryptAES256GCM : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()

public:

	/** Appelé si le déchiffrement réussit ET que le tag GCM est valide. */
	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnSuccess;

	/** Appelé si le déchiffrement échoue (tag invalide, données corrompues, etc.). */
	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnFailure;

	/**
	 * Lance un déchiffrement AES-256-GCM asynchrone avec dérivation PBKDF2.
	 *
	 * @param EncryptedPayload  Payload produit par EncryptBytes_AES256GCM.
	 * @param Password          Mot de passe utilisé au chiffrement.
	 * @param Iterations        Même nombre d'itérations qu'au chiffrement.
	 */
	UFUNCTION(BlueprintCallable,
		Category = "OpenSSL Crypto|Async",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "Async AES-256-GCM Decrypt (Password)",
			Keywords = "decrypt aes gcm async openssl"))
	static UAsyncDecryptAES256GCM* AsyncDecryptAES256GCM(
		const TArray<uint8>& EncryptedPayload,
		const FString&       Password,
		int32                Iterations = 100000);

	virtual void Activate() override;

private:
	TArray<uint8> EncryptedPayload;
	FString       Password;
	int32         Iterations = 100000;
};

// ── Encrypt async (clé brute) ────

/**
 * Chiffre un tableau d'octets de manière asynchrone avec une clé brute 32 octets
 */
UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncEncryptAES256GCM_RawKey : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()

public:

	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnFailure;

	/**
	 * Lance un chiffrement AES-256-GCM asynchrone avec clé brute
	 *
	 * @param Plaintext  Données à chiffrer.
	 * @param RawKey32   Clé AES-256 (exactement 32 octets)
	 */
	UFUNCTION(BlueprintCallable,
		Category = "OpenSSL Crypto|Async",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "Async AES-256-GCM Encrypt (Raw Key)",
			Keywords = "encrypt aes gcm async raw key openssl"))
	static UAsyncEncryptAES256GCM_RawKey* AsyncEncryptAES256GCM_RawKey(
		const TArray<uint8>& Plaintext,
		const TArray<uint8>& RawKey32);

	virtual void Activate() override;

private:
	TArray<uint8> Plaintext;
	TArray<uint8> RawKey32;
};

// ── Decrypt async (clé brute)

/**
 * Déchiffre un payload AES-256-GCM de manière asynchrone avec une clé brute
 */
UCLASS(meta = (HideCategories = "Object"))
class OPENSSLCRYPTO_API UAsyncDecryptAES256GCM_RawKey : public UBlueprintAsyncActionBase
{
	GENERATED_BODY()

public:

	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnSuccess;

	UPROPERTY(BlueprintAssignable)
	FOnCryptoComplete OnFailure;

	/**
	 * Lance un déchiffrement AES-256-GCM asynchrone avec clé brute
	 *
	 * @param EncryptedPayload  Payload produit par EncryptBytes_AES256GCM_RawKey
	 * @param RawKey32          Clé AES-256 (exactement 32 octets)
	 */
	UFUNCTION(BlueprintCallable,
		Category = "OpenSSL Crypto|Async",
		meta = (BlueprintInternalUseOnly = "true",
			DisplayName = "Async AES-256-GCM Decrypt (Raw Key)",
			Keywords = "decrypt aes gcm async raw key openssl"))
	static UAsyncDecryptAES256GCM_RawKey* AsyncDecryptAES256GCM_RawKey(
		const TArray<uint8>& EncryptedPayload,
		const TArray<uint8>& RawKey32);

	virtual void Activate() override;

private:
	TArray<uint8> EncryptedPayload;
	TArray<uint8> RawKey32;
};
