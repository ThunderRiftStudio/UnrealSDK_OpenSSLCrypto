#pragma once

/**
 * OpenSSLCryptoBPLibrary.h
 *
 * Bibliothèque Blueprint pour le chiffrement AES-256-GCM via OpenSSL 1.1.1t.
 *
 * FORMAT DU PAYLOAD CHIFFRÉ (TArray<uint8>) :
 * ┌──────────────┬───────────────┬─────────────────┬──────────────────────────┐
 * │  SALT        │  IV (Nonce)   │  AUTH TAG       │  CIPHERTEXT              │
 * │  16 bytes    │  12 bytes     │  16 bytes       │  N bytes (même taille    │
 * │  (PBKDF2)    │  (GCM nonce)  │  (GCM tag)      │  que le plaintext)       │
 * └──────────────┴───────────────┴─────────────────┴──────────────────────────┘
 * Taille totale = 44 + len(plaintext)
 *
 * Dérivation de clé : PBKDF2-HMAC-SHA256, 100 000 itérations, clé 256 bits.
 * Chiffrement      : AES-256-GCM (EVP_aes_256_gcm), IV 96 bits aléatoire.
 * Authenticité     : Tag GCM 128 bits vérifié à la décryption.
 *
 * SÉCURITÉ :
 *   - Ne jamais réutiliser un (clé, IV) identique.
 *   - La dérivation PBKDF2 génère un nouveau salt aléatoire à chaque chiffrement.
 *   - Le tag GCM protège l'intégrité : toute altération du payload est détectée.
 *   - Compatible fichiers binaires (pas de dépendance au null-terminator).
 */

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "OpenSSLCryptoBPLibrary.generated.h"

/**
 * Résultat d'une opération cryptographique.
 * Utilisez bSuccess pour vérifier le résultat avant d'utiliser les données.
 */
USTRUCT(BlueprintType)
struct OPENSSLCRYPTO_API FOpenSSLCryptoResult
{
	GENERATED_BODY()

	/** true si l'opération s'est terminée sans erreur */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto")
	bool bSuccess = false;

	/** Message d'erreur lisible (vide si succès) */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto")
	FString ErrorMessage;

	/** Données produites (payload chiffré ou plaintext selon l'opération) */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto")
	TArray<uint8> Data;
};

/**
 * UOpenSSLCryptoBPLibrary
 *
 * Fonctions Blueprint statiques pour le chiffrement/déchiffrement AES-256-GCM.
 * Toutes les opérations s'effectuent en mémoire sur des TArray<uint8>.
 */
UCLASS()
class OPENSSLCRYPTO_API UOpenSSLCryptoBPLibrary : public UBlueprintFunctionLibrary
{
	GENERATED_BODY()

public:

	// ─────────────────────────────────────────────────────────────────────────
	// CHIFFREMENT
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Chiffre un tableau d'octets avec AES-256-GCM.
	 *
	 * Génère automatiquement un salt PBKDF2 aléatoire et un IV GCM aléatoire.
	 * Le résultat contient : SALT(16) + IV(12) + TAG(16) + CIPHERTEXT(N).
	 *
	 * @param Plaintext     Données à chiffrer (peut être vide).
	 * @param Password      Mot de passe (dérivation PBKDF2-HMAC-SHA256).
	 * @param Iterations    Nombre d'itérations PBKDF2 (minimum recommandé : 100000).
	 * @return              FOpenSSLCryptoResult avec Data = payload chiffré.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|AES-256-GCM",
		meta = (DisplayName = "AES-256-GCM Encrypt (Password)",
			Keywords = "encrypt aes gcm openssl crypto",
			ToolTip = "Chiffre des octets avec AES-256-GCM et dérivation PBKDF2. Génère un salt et IV aléatoires."))
	static FOpenSSLCryptoResult EncryptBytes_AES256GCM(
		const TArray<uint8>& Plaintext,
		const FString& Password,
		int32 Iterations = 100000);

	/**
	 * Chiffre un tableau d'octets avec AES-256-GCM en utilisant une clé brute 256 bits.
	 *
	 * Aucune dérivation PBKDF2 — la clé est utilisée directement.
	 * La clé DOIT faire exactement 32 octets. Un IV GCM aléatoire est généré.
	 * Le résultat contient : IV(12) + TAG(16) + CIPHERTEXT(N).
	 *
	 * @param Plaintext     Données à chiffrer.
	 * @param RawKey32      Clé AES-256 brute (exactement 32 octets).
	 * @return              FOpenSSLCryptoResult avec Data = payload chiffré.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|AES-256-GCM",
		meta = (DisplayName = "AES-256-GCM Encrypt (Raw Key)",
			Keywords = "encrypt aes gcm raw key openssl",
			ToolTip = "Chiffre des octets avec AES-256-GCM et une clé brute 32 octets. IV aléatoire généré."))
	static FOpenSSLCryptoResult EncryptBytes_AES256GCM_RawKey(
		const TArray<uint8>& Plaintext,
		const TArray<uint8>& RawKey32);

	// ─────────────────────────────────────────────────────────────────────────
	// DÉCHIFFREMENT
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Déchiffre un payload AES-256-GCM produit par EncryptBytes_AES256GCM.
	 *
	 * Extrait automatiquement SALT, IV et TAG depuis le payload.
	 * Échoue (bSuccess=false) si le tag GCM est invalide (données corrompues/altérées).
	 *
	 * @param EncryptedPayload  Payload chiffré (SALT+IV+TAG+CIPHERTEXT).
	 * @param Password          Mot de passe utilisé lors du chiffrement.
	 * @param Iterations        Même nombre d'itérations PBKDF2 qu'au chiffrement.
	 * @return                  FOpenSSLCryptoResult avec Data = plaintext original.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|AES-256-GCM",
		meta = (DisplayName = "AES-256-GCM Decrypt (Password)",
			Keywords = "decrypt aes gcm openssl crypto",
			ToolTip = "Déchiffre un payload AES-256-GCM avec PBKDF2. Vérifie l'authenticité GCM."))
	static FOpenSSLCryptoResult DecryptBytes_AES256GCM(
		const TArray<uint8>& EncryptedPayload,
		const FString& Password,
		int32 Iterations = 100000);

	/**
	 * Déchiffre un payload AES-256-GCM produit par EncryptBytes_AES256GCM_RawKey.
	 *
	 * Extrait IV et TAG depuis le payload (format : IV(12)+TAG(16)+CIPHERTEXT).
	 * Échoue si le tag GCM est invalide.
	 *
	 * @param EncryptedPayload  Payload chiffré (IV+TAG+CIPHERTEXT).
	 * @param RawKey32          Clé AES-256 brute (exactement 32 octets).
	 * @return                  FOpenSSLCryptoResult avec Data = plaintext original.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|AES-256-GCM",
		meta = (DisplayName = "AES-256-GCM Decrypt (Raw Key)",
			Keywords = "decrypt aes gcm raw key openssl",
			ToolTip = "Déchiffre un payload AES-256-GCM avec une clé brute 32 octets."))
	static FOpenSSLCryptoResult DecryptBytes_AES256GCM_RawKey(
		const TArray<uint8>& EncryptedPayload,
		const TArray<uint8>& RawKey32);

	// ─────────────────────────────────────────────────────────────────────────
	// UTILITAIRES
	// ─────────────────────────────────────────────────────────────────────────

	/**
	 * Dérive une clé AES-256 depuis un mot de passe via PBKDF2-HMAC-SHA256.
	 *
	 * Expose la dérivation PBKDF2 directement pour des usages avancés.
	 * Vous devez fournir un salt (16 octets recommandés).
	 *
	 * @param Password      Mot de passe source.
	 * @param Salt          Salt (au moins 16 octets recommandés).
	 * @param Iterations    Nombre d'itérations (minimum 100000 recommandé).
	 * @param KeyLengthBytes  Taille de la clé souhaitée en octets (32 pour AES-256).
	 * @return              FOpenSSLCryptoResult avec Data = clé dérivée.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|Utilities",
		meta = (DisplayName = "PBKDF2-HMAC-SHA256 Derive Key",
			Keywords = "pbkdf2 hmac sha256 kdf key derive",
			ToolTip = "Dérive une clé depuis un mot de passe via PBKDF2-HMAC-SHA256."))
	static FOpenSSLCryptoResult DeriveKey_PBKDF2_HMACSHA256(
		const FString& Password,
		const TArray<uint8>& Salt,
		int32 Iterations = 100000,
		int32 KeyLengthBytes = 32);

	/**
	 * Génère N octets aléatoires cryptographiquement sûrs via RAND_bytes.
	 *
	 * @param NumBytes  Nombre d'octets a generer (1 a 268435456 = 256 Mo).
	 * @return          FOpenSSLCryptoResult avec Data = octets aléatoires.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|Utilities",
		meta = (DisplayName = "Generate Random Bytes (RAND_bytes)",
			Keywords = "random bytes rand openssl crypto",
			ToolTip = "Génère des octets aléatoires cryptographiquement sûrs via OpenSSL RAND_bytes."))
	static FOpenSSLCryptoResult GenerateRandomBytes(int64 NumBytes = 32);

	/**
	 * Convertit un TArray<uint8> en chaîne hexadécimale (pour debug/affichage).
	 *
	 * @param Bytes   Données binaires.
	 * @return        Représentation hexadécimale en majuscules.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Utilities",
		meta = (DisplayName = "Bytes To Hex String",
			Keywords = "hex bytes string convert",
			ToolTip = "Convertit un tableau d'octets en chaîne hexadécimale."))
	static FString BytesToHexString(const TArray<uint8>& Bytes);

	/**
	 * Convertit une chaîne hexadécimale en TArray<uint8>.
	 *
	 * @param HexString  Chaîne hex (longueur paire, ex: "DEADBEEF").
	 * @return           FOpenSSLCryptoResult avec Data = octets décodés.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|Utilities",
		meta = (DisplayName = "Hex String To Bytes",
			Keywords = "hex bytes string convert",
			ToolTip = "Convertit une chaîne hexadécimale en tableau d'octets."))
	static FOpenSSLCryptoResult HexStringToBytes(const FString& HexString);

	/**
	 * Convertit une FString UTF-8 en TArray<uint8> (pour chiffrer du texte).
	 *
	 * @param Text  Texte à convertir.
	 * @return      Octets UTF-8 sans null-terminator.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Utilities",
		meta = (DisplayName = "String To UTF8 Bytes",
			Keywords = "string bytes utf8 convert",
			ToolTip = "Convertit une chaîne en tableau d'octets UTF-8."))
	static TArray<uint8> StringToUTF8Bytes(const FString& Text);

	/**
	 * Convertit un TArray<uint8> UTF-8 en FString (après déchiffrement de texte).
	 *
	 * @param Bytes  Octets UTF-8.
	 * @return       Chaîne décodée.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Utilities",
		meta = (DisplayName = "UTF8 Bytes To String",
			Keywords = "bytes string utf8 convert",
			ToolTip = "Convertit des octets UTF-8 en chaîne."))
	static FString UTF8BytesToString(const TArray<uint8>& Bytes);
};
