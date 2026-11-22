#pragma once
#include "CoreMinimal.h"
#include "OpenSSLCryptoTypes.generated.h"

/**
 * Mode de parallelisme pour les noeuds MultiWorker.
 * Controle combien de cores physiques sont utilises pour le chiffrement.
 */
UENUM(BlueprintType)
enum class EOpenSSLWorkerMode : uint8
{
	Low  UMETA(DisplayName = "Multiworker Low  (Half Cores)"),
	High UMETA(DisplayName = "Multiworker High (All Cores - 1)"),
	Max  UMETA(DisplayName = "Multiworker Max  (All Cores)")
};

/**
 * Progression en temps reel d'une operation MultiWorker.
 * Diffuse via le pin OnProgress toutes les ~250ms.
 */
USTRUCT(BlueprintType)
struct OPENSSLCRYPTO_API FOpenSSLCryptoProgress
{
	GENERATED_BODY()

	/** Pourcentage de CPU logique denie aux workers (0-100) */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	float CPUUsedPercent = 0.f;

	/** Vitesse de traitement en Mo/s */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	float SpeedMBps = 0.f;

	/** Nombre de workers (chunks) actifs en ce moment */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	int32 WorkersActive = 0;

	/** Taille totale des donnees en Mo */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	float TotalMB = 0.f;

	/** Donnees traitees jusqu'ici en Mo */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	float CurrentMB = 0.f;

	/** Avancement global en pourcentage (0-100) */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	float ProgressPercent = 0.f;

	/** Nombre total de chunks */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	int32 NumChunks = 0;

	/** Chunks termines */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	int32 ChunksDone = 0;

	/** Temps ecoule depuis le debut (secondes) */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	float ElapsedSeconds = 0.f;

	/**
	 * true pendant la phase de derivation de cle PBKDF2 (decrypt Password uniquement).
	 * Pendant cette phase, ProgressPercent reste a 0 et WorkersActive = 0 — c'est normal.
	 * La derivation PBKDF2 ne peut pas etre parallelisee et dure ~100ms a 100k iterations.
	 */
	UPROPERTY(BlueprintReadOnly, Category = "OpenSSL Crypto|Progress")
	bool bKeyDerivationPhase = false;
};
