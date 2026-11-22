#pragma once

/**
 * OpenSSLCryptoTestActor.h
 *
 * Acteur de test/exemple pour valider le plugin depuis C++ et Blueprint.
 * Placez cet acteur dans une map de test, appuyez sur Play,
 * et consultez le Output Log (filtre "OpenSSLCrypto").
 *
 * Tous les tests sont également exposés en Blueprint via
 * les fonctions UFUNCTION ci-dessous.
 */

#include "CoreMinimal.h"
#include "GameFramework/Actor.h"
#include "OpenSSLCryptoTestActor.generated.h"

UCLASS()
class OPENSSLCRYPTO_API AOpenSSLCryptoTestActor : public AActor
{
	GENERATED_BODY()

public:
	AOpenSSLCryptoTestActor();

protected:
	virtual void BeginPlay() override;

public:

	/**
	 * Lance tous les tests de validation du plugin.
	 * Affiche les résultats dans le Output Log (catégorie "OpenSSLCrypto").
	 * Retourne true si tous les tests passent.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests",
		meta = (DisplayName = "Run All Crypto Tests"))
	bool RunAllCryptoTests();

	/**
	 * Test 1 : Chiffrement/déchiffrement aller-retour avec mot de passe.
	 * Vérifie que le plaintext original est retrouvé après déchiffrement.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_EncryptDecrypt_Password();

	/**
	 * Test 2 : Chiffrement/déchiffrement aller-retour avec clé brute.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_EncryptDecrypt_RawKey();

	/**
	 * Test 3 : Détection de tampering — modification du payload doit échouer au déchiffrement.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_TamperDetection();

	/**
	 * Test 4 : Données binaires arbitraires (tous les octets 0x00–0xFF).
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_BinaryData();

	/**
	 * Test 5 : Chiffrement d'un buffer vide (plaintext de taille 0).
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_EmptyPlaintext();

	/**
	 * Test 6 : PBKDF2 et génération aléatoire.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_PBKDF2_AndRandom();

	/**
	 * Test 7 : Mot de passe incorrect → déchiffrement doit échouer.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_WrongPassword();

	/**
	 * Test 8 : Deux chiffrements du même plaintext → payloads différents (IV aléatoire).
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_RandomIV_DifferentPayloads();

	/**
	 * Test 9 : Magic bytes — verification correcte et rejet si absent/incorrect.
	 */
	UFUNCTION(BlueprintCallable, CallInEditor, Category = "OpenSSL Crypto|Tests")
	bool Test_MagicBytes();

	/** Si true, lance les tests automatiquement au BeginPlay. */
	UPROPERTY(EditAnywhere, BlueprintReadWrite, Category = "OpenSSL Crypto|Tests")
	bool bRunTestsOnBeginPlay = true;
};
