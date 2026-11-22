#pragma once

/**
 * OpenSSLCryptoFileHelper.h
 *
 * ARCHITECTURE EN TROIS COUCHES :
 *
 * 1. FICHIER BRUT  (Encrypt/Decrypt File)
 *    Lit un fichier, chiffre/dechiffre, ecrit le resultat. Sans magic.
 *
 * 2. MAGIC EN MEMOIRE  (Prepend / Strip sur TArray<uint8>)
 *    Travaille uniquement sur des octets en memoire.
 *    Pas de fichier en entree ou sortie — zero fichier temporaire.
 *    Exemple :
 *      EncryptBytes → Data (payload chiffre)
 *      PrependMagicToBytes(Data, "PAK") → DataWithMagic (TArray<uint8>)
 *      WriteBytesToFile(DataWithMagic, "fichier.pak")
 *
 * 3. ALL-IN-ONE  (Encrypt+Magic ou Magic+Decrypt en une seule passe disque)
 *    Combine lecture, chiffrement, ajout/retrait magic et ecriture en memoire.
 *    1 lecture disque + 1 ecriture disque. Zero fichier temporaire.
 *    Le cas d'usage le plus courant en production.
 */

#include "CoreMinimal.h"
#include "Kismet/BlueprintFunctionLibrary.h"
#include "OpenSSLCryptoBPLibrary.h"
#include "OpenSSLCryptoFileHelper.generated.h"

UCLASS()
class OPENSSLCRYPTO_API UOpenSSLCryptoFileHelper : public UBlueprintFunctionLibrary
{
	GENERATED_BODY()

public:

	
	// 1. CHIFFREMENT / DECHIFFREMENT FICHIER  (sans magic)
	

	/**
	 * Lit un fichier, le chiffre avec AES-256-GCM (PBKDF2), ecrit le resultat.
	 * Format sortie : SALT(16) + IV(12) + TAG(16) + CIPHERTEXT.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File",
		meta = (DisplayName = "Encrypt File AES-256-GCM (Password)",
			Keywords = "encrypt file aes gcm openssl"))
	static FOpenSSLCryptoResult EncryptFile_AES256GCM(
		const FString& InputFilePath,
		const FString& OutputFilePath,
		const FString& Password,
		int32          Iterations = 100000);

	/**
	 * Lit un fichier chiffre, le dechiffre avec AES-256-GCM (PBKDF2), ecrit le plaintext.
	 * Echoue si le tag GCM est invalide.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File",
		meta = (DisplayName = "Decrypt File AES-256-GCM (Password)",
			Keywords = "decrypt file aes gcm openssl"))
	static FOpenSSLCryptoResult DecryptFile_AES256GCM(
		const FString& InputFilePath,
		const FString& OutputFilePath,
		const FString& Password,
		int32          Iterations = 100000);

	/**
	 * Lit un fichier, le chiffre avec AES-256-GCM (cle brute 32 octets), ecrit le resultat.
	 * Format sortie : IV(12) + TAG(16) + CIPHERTEXT.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File",
		meta = (DisplayName = "Encrypt File AES-256-GCM (Raw Key)",
			Keywords = "encrypt file aes gcm raw key openssl"))
	static FOpenSSLCryptoResult EncryptFile_AES256GCM_RawKey(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const TArray<uint8>& RawKey32);

	/**
	 * Lit un fichier chiffre, le dechiffre avec AES-256-GCM (cle brute 32 octets).
	 * Echoue si le tag GCM est invalide.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File",
		meta = (DisplayName = "Decrypt File AES-256-GCM (Raw Key)",
			Keywords = "decrypt file aes gcm raw key openssl"))
	static FOpenSSLCryptoResult DecryptFile_AES256GCM_RawKey(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const TArray<uint8>& RawKey32);

	
	// 2. MAGIC EN MEMOIRE  (sur TArray<uint8>, zero fichier temporaire)
	//
	// Ces noeuds ne touchent PAS au disque.
	// Ils operent sur des octets deja en memoire.
	//
	// Workflow typique :
	//   [Encrypt Bytes AES-256-GCM] → Data (payload chiffre en memoire)
	//   [Prepend Magic String To Bytes "PAK"] → DataWithMagic (en memoire)
	//   [Write Bytes To File] → fichier.pak  (1 seule ecriture disque)
	//
	//   [Read File To Bytes] fichier.pak → RawBytes  (1 seule lecture disque)
	//   [Strip And Check Magic String From Bytes "PAK"] → EncryptedPayload
	//   [Decrypt Bytes AES-256-GCM] → Plaintext
	

	/**
	 * Prepend une chaine ASCII en tete d'un TArray<uint8> en memoire.
	 * Retourne [magic bytes] + [InBytes]. Aucun fichier cree.
	 *
	 * @param InBytes      Payload sur lequel prepender (ex: resultat de EncryptBytes).
	 * @param MagicString  Chaine ASCII a coller en tete (ex: "PAK", "SAVE", "STCR").
	 * @return             Nouveau TArray<uint8> = MagicString + InBytes.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Prepend Magic String To Bytes",
			Keywords = "magic prepend prefix bytes memory pak save",
			ToolTip = "Colle une chaine ASCII en tete d'un tableau d'octets. Aucun fichier cree."))
	static TArray<uint8> PrependMagicStringToBytes(
		const TArray<uint8>& InBytes,
		const FString&       MagicString);

	/**
	 * Prepend des octets bruts en tete d'un TArray<uint8> en memoire.
	 * Retourne [MagicBytes] + [InBytes]. Aucun fichier cree.
	 *
	 * @param InBytes     Payload sur lequel prepender.
	 * @param MagicBytes  Octets a coller en tete.
	 * @return            Nouveau TArray<uint8> = MagicBytes + InBytes.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Prepend Magic Bytes To Bytes",
			Keywords = "magic prepend prefix bytes memory binary",
			ToolTip = "Colle des octets bruts en tete d'un tableau d'octets. Aucun fichier cree."))
	static TArray<uint8> PrependMagicBytesToBytes(
		const TArray<uint8>& InBytes,
		const TArray<uint8>& MagicBytes);

	/**
	 * Verifie que InBytes commence par MagicString, puis retourne InBytes sans ce prefixe.
	 * Tout se passe en memoire. Aucun fichier cree.
	 *
	 * @param InBytes      Tableau d'octets avec magic en tete (ex: lu depuis fichier.pak).
	 * @param MagicString  Magic attendu (meme valeur qu'au Prepend).
	 * @return             bSuccess=true + Data = InBytes sans le prefixe.
	 *                     bSuccess=false si magic invalide ou InBytes trop court.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Strip And Check Magic String From Bytes",
			Keywords = "magic strip check verify bytes memory pak",
			ToolTip = "Verifie le magic string en tete puis retourne les octets sans ce prefixe. Memoire uniquement."))
	static FOpenSSLCryptoResult StripAndCheckMagicStringFromBytes(
		const TArray<uint8>& InBytes,
		const FString&       MagicString);

	/**
	 * Verifie que InBytes commence par MagicBytes, puis retourne InBytes sans ce prefixe.
	 * Tout se passe en memoire. Aucun fichier cree.
	 *
	 * @param InBytes     Tableau d'octets avec magic en tete.
	 * @param MagicBytes  Magic attendu (meme valeur qu'au Prepend).
	 * @return            bSuccess=true + Data = InBytes sans le prefixe.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Strip And Check Magic Bytes From Bytes",
			Keywords = "magic strip check verify bytes memory binary",
			ToolTip = "Verifie les magic bytes en tete puis retourne les octets sans ce prefixe. Memoire uniquement."))
	static FOpenSSLCryptoResult StripAndCheckMagicBytesFromBytes(
		const TArray<uint8>& InBytes,
		const TArray<uint8>& MagicBytes);

	/**
	 * Verifie si InBytes commence par MagicString. Ne modifie rien.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Bytes Have Magic String",
			Keywords = "magic check bytes header format identify string",
			ToolTip = "Retourne true si le tableau d'octets commence par la chaine magique."))
	static bool BytesHaveMagicString(
		const TArray<uint8>& InBytes,
		const FString&       MagicString);

	/**
	 * Verifie si InBytes commence par MagicBytes. Ne modifie rien.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Bytes Have Magic Bytes",
			Keywords = "magic check bytes header format identify binary",
			ToolTip = "Retourne true si le tableau d'octets commence par les octets magiques."))
	static bool BytesHaveMagicBytes(
		const TArray<uint8>& InBytes,
		const TArray<uint8>& MagicBytes);

	/**
	 * Convertit une chaine ASCII en TArray<uint8>.
	 * Exemple : "PAK" -> {0x50, 0x41, 0x4B}
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|Magic|Memory",
		meta = (DisplayName = "Make Magic Bytes From String",
			Keywords = "magic bytes ascii string convert",
			ToolTip = "Convertit une chaine ASCII en octets. Ex: PAK -> {0x50,0x41,0x4B}"))
	static TArray<uint8> MakeMagicBytesFromString(const FString& AsciiString);

	
	// 3. ALL-IN-ONE  (Encrypt+Magic ou Magic+Decrypt, 1 read + 1 write disque)
	//
	// Combine tout en memoire : lecture, chiffrement, prepend/strip magic,
	// ecriture. Zero fichier temporaire. La solution la plus efficace.
	//
	// Workflow chiffrement :
	//   Read(input) → bytes                     [1 lecture disque]
	//   EncryptBytes(bytes) → encryptedPayload  [memoire]
	//   Output = magic + encryptedPayload        [memoire]
	//   Write(Output)                            [1 ecriture disque]
	//
	// Workflow dechiffrement :
	//   Read(input) → rawFile                   [1 lecture disque]
	//   CheckMagic + strip → encryptedPayload   [memoire]
	//   DecryptBytes(encryptedPayload)           [memoire]
	//   Write(plaintext)                         [1 ecriture disque]
	

	/**
	 * Chiffre un fichier et ecrit [MagicString + payload chiffre] en une seule
	 * passe disque. Zero fichier temporaire.
	 * Format : [MagicString bytes][SALT 16][IV 12][TAG 16][CIPHERTEXT]
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Encrypt File With Magic String (Password)",
			Keywords = "encrypt file magic string aes gcm openssl pak save all in one",
			ToolTip = "Chiffre un fichier et ecrit magic+payload en une seule passe. Zero fichier temporaire."))
	static FOpenSSLCryptoResult EncryptFileWithMagicString_AES256GCM(
		const FString& InputFilePath,
		const FString& OutputFilePath,
		const FString& Password,
		const FString& MagicString,
		int32          Iterations = 100000);

	/**
	 * Verifie le magic string, le retire en memoire, dechiffre et ecrit le plaintext.
	 * Zero fichier temporaire.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Decrypt File With Magic String (Password)",
			Keywords = "decrypt file magic string aes gcm openssl pak save all in one",
			ToolTip = "Verifie le magic, strip et dechiffre en une seule passe. Zero fichier temporaire."))
	static FOpenSSLCryptoResult DecryptFileWithMagicString_AES256GCM(
		const FString& InputFilePath,
		const FString& OutputFilePath,
		const FString& Password,
		const FString& MagicString,
		int32          Iterations = 100000);

	/**
	 * Chiffre un fichier (cle brute) et ecrit [MagicString + payload] en une seule passe.
	 * Zero fichier temporaire.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Encrypt File With Magic String (Raw Key)",
			Keywords = "encrypt file magic string aes gcm raw key all in one",
			ToolTip = "Chiffre (cle brute) et ecrit magic+payload en une seule passe. Zero fichier temporaire."))
	static FOpenSSLCryptoResult EncryptFileWithMagicString_AES256GCM_RawKey(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const TArray<uint8>& RawKey32,
		const FString&       MagicString);

	/**
	 * Verifie le magic string, strip en memoire, dechiffre (cle brute), ecrit.
	 * Zero fichier temporaire.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Decrypt File With Magic String (Raw Key)",
			Keywords = "decrypt file magic string aes gcm raw key all in one",
			ToolTip = "Verifie le magic, strip et dechiffre (cle brute) en une seule passe. Zero fichier temporaire."))
	static FOpenSSLCryptoResult DecryptFileWithMagicString_AES256GCM_RawKey(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const TArray<uint8>& RawKey32,
		const FString&       MagicString);

	/**
	 * Chiffre un fichier et ecrit [MagicBytes + payload] en une seule passe.
	 * Zero fichier temporaire. Variante octets bruts.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Encrypt File With Magic Bytes (Password)",
			Keywords = "encrypt file magic bytes aes gcm all in one binary"))
	static FOpenSSLCryptoResult EncryptFileWithMagicBytes_AES256GCM(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const FString&       Password,
		const TArray<uint8>& MagicBytes,
		int32                Iterations = 100000);

	/**
	 * Verifie les magic bytes, strip en memoire, dechiffre, ecrit.
	 * Zero fichier temporaire. Variante octets bruts.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Decrypt File With Magic Bytes (Password)",
			Keywords = "decrypt file magic bytes aes gcm all in one binary"))
	static FOpenSSLCryptoResult DecryptFileWithMagicBytes_AES256GCM(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const FString&       Password,
		const TArray<uint8>& MagicBytes,
		int32                Iterations = 100000);

	/**
	 * Chiffre un fichier (cle brute) et ecrit [MagicBytes + payload] en une seule passe.
	 * Zero fichier temporaire. Variante octets bruts + cle brute.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Encrypt File With Magic Bytes (Raw Key)",
			Keywords = "encrypt file magic bytes aes gcm raw key all in one"))
	static FOpenSSLCryptoResult EncryptFileWithMagicBytes_AES256GCM_RawKey(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const TArray<uint8>& RawKey32,
		const TArray<uint8>& MagicBytes);

	/**
	 * Verifie les magic bytes, strip en memoire, dechiffre (cle brute), ecrit.
	 * Zero fichier temporaire. Variante octets bruts + cle brute.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|All-In-One",
		meta = (DisplayName = "Decrypt File With Magic Bytes (Raw Key)",
			Keywords = "decrypt file magic bytes aes gcm raw key all in one"))
	static FOpenSSLCryptoResult DecryptFileWithMagicBytes_AES256GCM_RawKey(
		const FString&       InputFilePath,
		const FString&       OutputFilePath,
		const TArray<uint8>& RawKey32,
		const TArray<uint8>& MagicBytes);

	
	// UTILITAIRES FICHIER
	

	/**
	 * Lit un fichier binaire entier dans un TArray<uint8>.
	 * Utile pour charger un fichier puis operer sur les octets en memoire.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|Utils",
		meta = (DisplayName = "Read File To Bytes",
			Keywords = "read file bytes binary load"))
	static FOpenSSLCryptoResult ReadFileToBytes(const FString& FilePath);

	/**
	 * Ecrit un TArray<uint8> dans un fichier binaire (ecrase si existant).
	 * Cree les dossiers parents si necessaires.
	 */
	UFUNCTION(BlueprintCallable, Category = "OpenSSL Crypto|File|Utils",
		meta = (DisplayName = "Write Bytes To File",
			Keywords = "write file bytes binary save"))
	static FOpenSSLCryptoResult WriteBytesToFile(
		const FString&       FilePath,
		const TArray<uint8>& Data);

	/**
	 * Verifie si un fichier commence par une chaine magique.
	 * Lit seulement les N premiers octets, n'importe pas tout le fichier.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|File|Utils",
		meta = (DisplayName = "File Has Magic String",
			Keywords = "magic check file header format identify"))
	static bool FileHasMagicString(
		const FString& FilePath,
		const FString& MagicString);

	/**
	 * Verifie si un fichier commence par des magic bytes.
	 * Lit seulement les N premiers octets.
	 */
	UFUNCTION(BlueprintPure, Category = "OpenSSL Crypto|File|Utils",
		meta = (DisplayName = "File Has Magic Bytes",
			Keywords = "magic check file header format binary"))
	static bool FileHasMagicBytes(
		const FString&       FilePath,
		const TArray<uint8>& MagicBytes);
};
