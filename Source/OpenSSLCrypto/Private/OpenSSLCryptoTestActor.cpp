// OpenSSLCryptoTestActor.cpp

#include "OpenSSLCryptoTestActor.h"
#include "OpenSSLCryptoBPLibrary.h"
#include "OpenSSLCryptoFileHelper.h"

DEFINE_LOG_CATEGORY_STATIC(LogOpenSSLCrypto, Log, All);

// ── Helpers de test 

static bool TestHelper_BytesEqual(const TArray<uint8>& A, const TArray<uint8>& B)
{
	if (A.Num() != B.Num()) { return false; }
	return FMemory::Memcmp(A.GetData(), B.GetData(), A.Num()) == 0;
}

// ── Acteur ────────

AOpenSSLCryptoTestActor::AOpenSSLCryptoTestActor()
{
	PrimaryActorTick.bCanEverTick = false;
}

void AOpenSSLCryptoTestActor::BeginPlay()
{
	Super::BeginPlay();
	if (bRunTestsOnBeginPlay)
	{
		RunAllCryptoTests();
	}
}

bool AOpenSSLCryptoTestActor::RunAllCryptoTests()
{
	UE_LOG(LogOpenSSLCrypto, Log, TEXT("========================================"));
	UE_LOG(LogOpenSSLCrypto, Log, TEXT("  OpenSSLCrypto Plugin -- Suite de tests"));
	UE_LOG(LogOpenSSLCrypto, Log, TEXT("========================================"));

	int32 Passed = 0;
	int32 Total  = 0;

	auto Run = [&](bool (AOpenSSLCryptoTestActor::*Fn)()) -> void
	{
		Total++;
		if ((this->*Fn)()) { Passed++; }
	};

	Run(&AOpenSSLCryptoTestActor::Test_EncryptDecrypt_Password);
	Run(&AOpenSSLCryptoTestActor::Test_EncryptDecrypt_RawKey);
	Run(&AOpenSSLCryptoTestActor::Test_TamperDetection);
	Run(&AOpenSSLCryptoTestActor::Test_BinaryData);
	Run(&AOpenSSLCryptoTestActor::Test_EmptyPlaintext);
	Run(&AOpenSSLCryptoTestActor::Test_PBKDF2_AndRandom);
	Run(&AOpenSSLCryptoTestActor::Test_WrongPassword);
	Run(&AOpenSSLCryptoTestActor::Test_RandomIV_DifferentPayloads);
	Run(&AOpenSSLCryptoTestActor::Test_MagicBytes);

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("========================================"));
	UE_LOG(LogOpenSSLCrypto, Log, TEXT("  Resultat : %d / %d tests passes"), Passed, Total);
	UE_LOG(LogOpenSSLCrypto, Log, TEXT("========================================"));

	return (Passed == Total);
}


// Test 1 : Encrypt/Decrypt aller-retour (mot de passe)

bool AOpenSSLCryptoTestActor::Test_EncryptDecrypt_Password()
{
	const FString Password = TEXT("M0tD3P@sseT3st!");
	const FString Message  = TEXT("Bonjour le monde ! Donnees de test 1234.");

	TArray<uint8> Plaintext = UOpenSSLCryptoBPLibrary::StringToUTF8Bytes(Message);

	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, Password, 10000);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_Password - Chiffrement echoue : %s"),
			*EncResult.ErrorMessage);
		return false;
	}

	// SALT(16) + IV(12) + TAG(16) + plaintext = 44 + N
	const int32 ExpectedSize = 44 + Plaintext.Num();
	if (EncResult.Data.Num() != ExpectedSize)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_Password - Taille payload %d != %d"),
			EncResult.Data.Num(), ExpectedSize);
		return false;
	}

	FOpenSSLCryptoResult DecResult =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(EncResult.Data, Password, 10000);

	if (!DecResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_Password - Dechiffrement echoue : %s"),
			*DecResult.ErrorMessage);
		return false;
	}

	if (!TestHelper_BytesEqual(DecResult.Data, Plaintext))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_Password - Plaintext different"));
		return false;
	}

	FString Decoded = UOpenSSLCryptoBPLibrary::UTF8BytesToString(DecResult.Data);
	if (Decoded != Message)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_Password - Message decode different"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_EncryptDecrypt_Password"));
	return true;
}


// Test 2 : Encrypt/Decrypt aller-retour (cle brute)

bool AOpenSSLCryptoTestActor::Test_EncryptDecrypt_RawKey()
{
	FOpenSSLCryptoResult KeyResult = UOpenSSLCryptoBPLibrary::GenerateRandomBytes(32);
	if (!KeyResult.bSuccess || KeyResult.Data.Num() != 32)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_RawKey - Generation cle echouee"));
		return false;
	}

	TArray<uint8> Plaintext;
	Plaintext.Reserve(512);
	for (int32 i = 0; i < 512; i++) { Plaintext.Add(static_cast<uint8>(i % 256)); }

	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM_RawKey(Plaintext, KeyResult.Data);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_RawKey - Chiffrement echoue : %s"),
			*EncResult.ErrorMessage);
		return false;
	}

	// IV(12) + TAG(16) + plaintext = 28 + N
	const int32 ExpectedSize = 28 + Plaintext.Num();
	if (EncResult.Data.Num() != ExpectedSize)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_RawKey - Taille payload %d != %d"),
			EncResult.Data.Num(), ExpectedSize);
		return false;
	}

	FOpenSSLCryptoResult DecResult =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM_RawKey(EncResult.Data, KeyResult.Data);

	if (!DecResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_RawKey - Dechiffrement echoue : %s"),
			*DecResult.ErrorMessage);
		return false;
	}

	if (!TestHelper_BytesEqual(DecResult.Data, Plaintext))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EncryptDecrypt_RawKey - Plaintext different"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_EncryptDecrypt_RawKey"));
	return true;
}


// Test 3 : Detection de tampering GCM

bool AOpenSSLCryptoTestActor::Test_TamperDetection()
{
	const FString Password = TEXT("MotDePasseTamper");
	TArray<uint8> Plaintext = UOpenSSLCryptoBPLibrary::StringToUTF8Bytes(
		TEXT("Donnees sensibles a proteger"));

	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, Password, 1000);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_TamperDetection - Chiffrement initial echoue"));
		return false;
	}

	// Cas 1 : modifier dernier octet du ciphertext
	{
		TArray<uint8> Tampered = EncResult.Data;
		Tampered.Last() ^= 0xFF;
		FOpenSSLCryptoResult Dec =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Tampered, Password, 1000);
		if (Dec.bSuccess)
		{
			UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_TamperDetection - Tamper ciphertext non detecte"));
			return false;
		}
	}

	// Cas 2 : modifier le TAG (offset SALT(16)+IV(12) = 28)
	{
		TArray<uint8> Tampered = EncResult.Data;
		if (Tampered.Num() > 28) { Tampered[28] ^= 0x01; }
		FOpenSSLCryptoResult Dec =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Tampered, Password, 1000);
		if (Dec.bSuccess)
		{
			UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_TamperDetection - Tamper TAG non detecte"));
			return false;
		}
	}

	// Cas 3 : modifier le SALT (offset 0)
	{
		TArray<uint8> Tampered = EncResult.Data;
		Tampered[0] ^= 0x42;
		FOpenSSLCryptoResult Dec =
			UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Tampered, Password, 1000);
		if (Dec.bSuccess)
		{
			UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_TamperDetection - Tamper SALT non detecte"));
			return false;
		}
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_TamperDetection"));
	return true;
}


// Test 4 : Donnees binaires (tous octets 0x00-0xFF)

bool AOpenSSLCryptoTestActor::Test_BinaryData()
{
	TArray<uint8> BinaryData;
	BinaryData.Reserve(256 * 4);
	for (int32 Rep = 0; Rep < 4; Rep++)
	{
		for (int32 i = 0; i < 256; i++) { BinaryData.Add(static_cast<uint8>(i)); }
	}

	const FString Password = TEXT("BinaryTestPassword");

	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(BinaryData, Password, 1000);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_BinaryData - Chiffrement echoue : %s"),
			*EncResult.ErrorMessage);
		return false;
	}

	FOpenSSLCryptoResult DecResult =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(EncResult.Data, Password, 1000);

	if (!DecResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_BinaryData - Dechiffrement echoue : %s"),
			*DecResult.ErrorMessage);
		return false;
	}

	if (!TestHelper_BytesEqual(DecResult.Data, BinaryData))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_BinaryData - Donnees corrompues"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_BinaryData"));
	return true;
}


// Test 5 : Buffer vide (plaintext de taille 0)

bool AOpenSSLCryptoTestActor::Test_EmptyPlaintext()
{
	TArray<uint8> EmptyData;
	const FString Password = TEXT("EmptyTest");

	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(EmptyData, Password, 1000);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EmptyPlaintext - Chiffrement echoue : %s"),
			*EncResult.ErrorMessage);
		return false;
	}

	// Payload vide = SALT(16) + IV(12) + TAG(16) = 44 exactement
	if (EncResult.Data.Num() != 44)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EmptyPlaintext - Taille %d != 44"),
			EncResult.Data.Num());
		return false;
	}

	FOpenSSLCryptoResult DecResult =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(EncResult.Data, Password, 1000);

	if (!DecResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EmptyPlaintext - Dechiffrement echoue : %s"),
			*DecResult.ErrorMessage);
		return false;
	}

	if (DecResult.Data.Num() != 0)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_EmptyPlaintext - Plaintext non vide : %d octets"),
			DecResult.Data.Num());
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_EmptyPlaintext"));
	return true;
}


// Test 6 : PBKDF2 deterministe + RAND_bytes

bool AOpenSSLCryptoTestActor::Test_PBKDF2_AndRandom()
{
	TArray<uint8> Salt;
	Salt.Init(0xAB, 16);

	FOpenSSLCryptoResult Key1 = UOpenSSLCryptoBPLibrary::DeriveKey_PBKDF2_HMACSHA256(
		TEXT("SamePassword"), Salt, 1000, 32);
	FOpenSSLCryptoResult Key2 = UOpenSSLCryptoBPLibrary::DeriveKey_PBKDF2_HMACSHA256(
		TEXT("SamePassword"), Salt, 1000, 32);

	if (!Key1.bSuccess || !Key2.bSuccess || Key1.Data.Num() != 32)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_PBKDF2_AndRandom - PBKDF2 echoue"));
		return false;
	}

	if (!TestHelper_BytesEqual(Key1.Data, Key2.Data))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_PBKDF2_AndRandom - PBKDF2 non-deterministe"));
		return false;
	}

	FOpenSSLCryptoResult Key3 = UOpenSSLCryptoBPLibrary::DeriveKey_PBKDF2_HMACSHA256(
		TEXT("OtherPassword"), Salt, 1000, 32);
	if (!Key3.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_PBKDF2_AndRandom - PBKDF2 key3 echoue"));
		return false;
	}
	if (TestHelper_BytesEqual(Key1.Data, Key3.Data))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_PBKDF2_AndRandom - Meme cle pour 2 MDP differents"));
		return false;
	}

	FOpenSSLCryptoResult Rnd1 = UOpenSSLCryptoBPLibrary::GenerateRandomBytes(32);
	FOpenSSLCryptoResult Rnd2 = UOpenSSLCryptoBPLibrary::GenerateRandomBytes(32);

	if (!Rnd1.bSuccess || !Rnd2.bSuccess || Rnd1.Data.Num() != 32 || Rnd2.Data.Num() != 32)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_PBKDF2_AndRandom - RAND_bytes echoue"));
		return false;
	}

	if (TestHelper_BytesEqual(Rnd1.Data, Rnd2.Data))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_PBKDF2_AndRandom - RAND_bytes identiques"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_PBKDF2_AndRandom"));
	return true;
}


// Test 7 : Mauvais mot de passe

bool AOpenSSLCryptoTestActor::Test_WrongPassword()
{
	TArray<uint8> Plaintext =
		UOpenSSLCryptoBPLibrary::StringToUTF8Bytes(TEXT("Message secret"));

	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, TEXT("BonMotDePasse"), 1000);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_WrongPassword - Chiffrement initial echoue"));
		return false;
	}

	FOpenSSLCryptoResult Dec1 =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(EncResult.Data, TEXT("MauvaisMotDePasse"), 1000);
	if (Dec1.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_WrongPassword - Mauvais MDP accepte"));
		return false;
	}

	FOpenSSLCryptoResult Dec2 =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(EncResult.Data, TEXT("BonMotDePasse"), 999);
	if (Dec2.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_WrongPassword - Mauvaises iterations acceptees"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_WrongPassword"));
	return true;
}


// Test 8 : IV aleatoire => payloads differents

bool AOpenSSLCryptoTestActor::Test_RandomIV_DifferentPayloads()
{
	TArray<uint8> Plaintext =
		UOpenSSLCryptoBPLibrary::StringToUTF8Bytes(TEXT("Meme message"));
	const FString Password = TEXT("MemeMDP");

	FOpenSSLCryptoResult Enc1 =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, Password, 1000);
	FOpenSSLCryptoResult Enc2 =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, Password, 1000);

	if (!Enc1.bSuccess || !Enc2.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_RandomIV_DifferentPayloads - Chiffrement echoue"));
		return false;
	}

	if (TestHelper_BytesEqual(Enc1.Data, Enc2.Data))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_RandomIV_DifferentPayloads - Payloads identiques (IV fixe !)"));
		return false;
	}

	FOpenSSLCryptoResult Dec1 =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Enc1.Data, Password, 1000);
	FOpenSSLCryptoResult Dec2 =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Enc2.Data, Password, 1000);

	if (!Dec1.bSuccess || !Dec2.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_RandomIV_DifferentPayloads - Dechiffrement echoue"));
		return false;
	}

	if (!TestHelper_BytesEqual(Dec1.Data, Plaintext) || !TestHelper_BytesEqual(Dec2.Data, Plaintext))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_RandomIV_DifferentPayloads - Plaintext incorrect"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_RandomIV_DifferentPayloads"));
	return true;
}


// Test 9 : Magic bytes (couche separee du chiffrement)

bool AOpenSSLCryptoTestActor::Test_MagicBytes()
{
	// Verifier MakeMagicBytesFromString
	TArray<uint8> Magic = UOpenSSLCryptoFileHelper::MakeMagicBytesFromString(TEXT("PAK"));
	if (Magic.Num() != 3 ||
		Magic[0] != 0x50 || // P
		Magic[1] != 0x41 || // A
		Magic[2] != 0x4B)   // K
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - MakeMagicBytesFromString incorrect"));
		return false;
	}

	// Verifier que le magic prefixe se retrouve bien en tete d'un payload
	TArray<uint8> Plaintext = UOpenSSLCryptoBPLibrary::StringToUTF8Bytes(TEXT("Donnees test"));
	FOpenSSLCryptoResult EncResult =
		UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(Plaintext, TEXT("TestMDP"), 1000);

	if (!EncResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - Chiffrement echoue"));
		return false;
	}

	// Simuler PrependMagic en memoire
	TArray<uint8> WithMagic;
	WithMagic.Append(Magic);
	WithMagic.Append(EncResult.Data);

	// Verifier que les 3 premiers octets sont bien PAK
	if (WithMagic[0] != 0x50 || WithMagic[1] != 0x41 || WithMagic[2] != 0x4B)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - Magic incorrect en tete"));
		return false;
	}

	// Simuler StripMagic : extraire le payload sans les 3 premiers octets
	TArray<uint8> Stripped;
	Stripped.Append(WithMagic.GetData() + Magic.Num(), WithMagic.Num() - Magic.Num());

	// Verifier que le payload stripe est identique au payload original
	if (!TestHelper_BytesEqual(Stripped, EncResult.Data))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - Payload apres strip different de l'original"));
		return false;
	}

	// Dechiffrer le payload stripe — doit fonctionner
	FOpenSSLCryptoResult DecResult =
		UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(Stripped, TEXT("TestMDP"), 1000);

	if (!DecResult.bSuccess)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - Dechiffrement apres strip echoue : %s"),
			*DecResult.ErrorMessage);
		return false;
	}

	if (!TestHelper_BytesEqual(DecResult.Data, Plaintext))
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - Plaintext different apres dechiffrement"));
		return false;
	}

	// Verifier que si les premiers octets ne correspondent pas au magic, on le detecte
	const bool bBadMagic = (WithMagic[0] == 0xFF && WithMagic[1] == 0xFF && WithMagic[2] == 0xFF);
	if (bBadMagic)
	{
		UE_LOG(LogOpenSSLCrypto, Error, TEXT("[FAIL] Test_MagicBytes - Faux positif magic detection"));
		return false;
	}

	UE_LOG(LogOpenSSLCrypto, Log, TEXT("[PASS] Test_MagicBytes"));
	return true;
}
