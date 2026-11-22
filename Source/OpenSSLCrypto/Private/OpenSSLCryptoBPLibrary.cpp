// OpenSSLCryptoBPLibrary.cpp
//
// AES-256-GCM via OpenSSL 1.1.1t (EVP only)
//
//   AES-256-GCM via EVP_aes_256_gcm()
//   IV 96 bits aléatoire via RAND_bytes()
//   Tag GCM 128 bits généré + check
//   PKCS5_PBKDF2_HMAC + EVP_sha256()
//   Salt 128 bits aléatoire par opération
//   Données binaires (TArray<uint8>)
//   EVP_CIPHER_CTX_free() dans tous les chemins

#include "OpenSSLCryptoBPLibrary.h"

// Wrapper qui bloque openssl/ui.h avant son inclusion transitive par evp.h
// Voir OpenSSLCryptoIncludes.h pour l'explication complète
#include "OpenSSLCryptoIncludes.h"

// Constantes de protocole
namespace OpenSSLCryptoConstants
{
	constexpr int32 AES_KEY_BYTES     = 32;
	constexpr int32 GCM_IV_BYTES      = 12;
	constexpr int32 GCM_TAG_BYTES     = 16;
	constexpr int32 PBKDF2_SALT_BYTES = 16;
	constexpr int32 MIN_PASSWORD_PAYLOAD = PBKDF2_SALT_BYTES + GCM_IV_BYTES + GCM_TAG_BYTES; // 44
	constexpr int32 MIN_RAWKEY_PAYLOAD   = GCM_IV_BYTES + GCM_TAG_BYTES;                      // 28
	constexpr int32 PBKDF2_MIN_ITERATIONS = 1;
	constexpr int32 PBKDF2_MAX_ITERATIONS = 10000000;
	// TArray<uint8> utilise int32 en interne donc la vraie limite est INT32_MAX (env 2 Go)
	constexpr int64 RAND_MAX_BYTES = (int64)MAX_int32; // env 2 Go
}

// Helpers préfixés CryptoHelper_ pour éviter tout conflit avec UE globals

static FString CryptoHelper_GetOpenSSLError()
{
	char ErrBuf[256] = { 0 };
	unsigned long ErrCode = ERR_get_error();
	if (ErrCode == 0)
	{
		return FString(TEXT("Unknown OpenSSL error"));
	}
	ERR_error_string_n(ErrCode, ErrBuf, sizeof(ErrBuf));
	return FString(UTF8_TO_TCHAR(ErrBuf));
}

static void CryptoHelper_ClearErrors()
{
	ERR_clear_error();
}

static FOpenSSLCryptoResult CryptoHelper_Err(const FString& Message)
{
	FOpenSSLCryptoResult R;
	R.bSuccess     = false;
	R.ErrorMessage = Message;
	return R;
}

static FOpenSSLCryptoResult CryptoHelper_ErrLiteral(const TCHAR* Message)
{
	FOpenSSLCryptoResult R;
	R.bSuccess     = false;
	R.ErrorMessage = FString(Message);
	return R;
}

static FOpenSSLCryptoResult CryptoHelper_Ok(TArray<uint8>&& Data)
{
	FOpenSSLCryptoResult R;
	R.bSuccess = true;
	R.Data     = MoveTemp(Data);
	return R;
}

static FOpenSSLCryptoResult CryptoHelper_OkEmpty()
{
	FOpenSSLCryptoResult R;
	R.bSuccess = true;
	return R;
}

static bool CryptoHelper_GenRandom(TArray<uint8>& OutBytes, int32 NumBytes)
{
	OutBytes.SetNumUninitialized(NumBytes);
	if (RAND_bytes(OutBytes.GetData(), NumBytes) != 1)
	{
		OutBytes.Empty();
		return false;
	}
	return true;
}

static bool CryptoHelper_PBKDF2(
	const uint8* PasswordUTF8, int32 PasswordLen,
	const uint8* Salt,         int32 SaltLen,
	int32        Iterations,
	uint8*       OutKey)
{
	return PKCS5_PBKDF2_HMAC(
		reinterpret_cast<const char*>(PasswordUTF8),
		PasswordLen,
		Salt,
		SaltLen,
		Iterations,
		EVP_sha256(),
		OpenSSLCryptoConstants::AES_KEY_BYTES,
		OutKey
	) == 1;
}

static bool CryptoHelper_Encrypt(
	const uint8*         Key,
	const uint8*         IV,
	const TArray<uint8>& Plaintext,
	TArray<uint8>&       OutCipher,
	uint8*               OutTag)
{
	using namespace OpenSSLCryptoConstants;

	EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
	if (!Ctx) { return false; }

	bool bOK = false;
	do
	{
		if (EVP_EncryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { break; }
		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_BYTES, nullptr) != 1) { break; }
		if (EVP_EncryptInit_ex(Ctx, nullptr, nullptr, Key, IV) != 1) { break; }

		const int32 PlainLen = Plaintext.Num();
		OutCipher.SetNumUninitialized(PlainLen);

		if (PlainLen > 0)
		{
			int OutLen = 0;
			if (EVP_EncryptUpdate(Ctx, OutCipher.GetData(), &OutLen,
				Plaintext.GetData(), PlainLen) != 1) { break; }
			if (OutLen != PlainLen) { break; }
		}

		{
			int FinalLen = 0;
			if (EVP_EncryptFinal_ex(Ctx, nullptr, &FinalLen) != 1) { break; }
		}

		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_BYTES, OutTag) != 1) { break; }

		bOK = true;
	} while (false);

	EVP_CIPHER_CTX_free(Ctx);
	if (!bOK) { OutCipher.Empty(); }
	return bOK;
}

static bool CryptoHelper_Decrypt(
	const uint8* Key,
	const uint8* IV,
	const uint8* Ciphertext, int32 CiphertextLen,
	const uint8* Tag,
	TArray<uint8>& OutPlain)
{
	using namespace OpenSSLCryptoConstants;

	EVP_CIPHER_CTX* Ctx = EVP_CIPHER_CTX_new();
	if (!Ctx) { return false; }

	bool bOK = false;
	do
	{
		if (EVP_DecryptInit_ex(Ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) { break; }
		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_IV_BYTES, nullptr) != 1) { break; }
		if (EVP_DecryptInit_ex(Ctx, nullptr, nullptr, Key, IV) != 1) { break; }

		OutPlain.SetNumUninitialized(CiphertextLen);

		if (CiphertextLen > 0)
		{
			int OutLen = 0;
			if (EVP_DecryptUpdate(Ctx, OutPlain.GetData(), &OutLen,
				Ciphertext, CiphertextLen) != 1) { break; }
		}

		if (EVP_CIPHER_CTX_ctrl(Ctx, EVP_CTRL_GCM_SET_TAG,
			GCM_TAG_BYTES, const_cast<uint8*>(Tag)) != 1) { break; }

		{
			int FinalLen = 0;
			int Ret = EVP_DecryptFinal_ex(Ctx, nullptr, &FinalLen);
			if (Ret <= 0)
			{
				EVP_CIPHER_CTX_free(Ctx);
				OutPlain.Empty();
				return false;
			}
		}

		bOK = true;
	} while (false);

	EVP_CIPHER_CTX_free(Ctx);
	if (!bOK) { OutPlain.Empty(); }
	return bOK;
}

// API publique

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM(
	const TArray<uint8>& Plaintext,
	const FString& Password,
	int32 Iterations)
{
	using namespace OpenSSLCryptoConstants;
	CryptoHelper_ClearErrors();

	if (Password.IsEmpty())
		return CryptoHelper_ErrLiteral(TEXT("Le mot de passe ne peut pas être vide."));

	if (Iterations < PBKDF2_MIN_ITERATIONS || Iterations > PBKDF2_MAX_ITERATIONS)
		return CryptoHelper_Err(FString::Printf(
			TEXT("Iterations invalide : doit être entre %d et %d."),
			PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS));

	TArray<uint8> Salt;
	if (!CryptoHelper_GenRandom(Salt, PBKDF2_SALT_BYTES))
		return CryptoHelper_Err(FString::Printf(
			TEXT("RAND_bytes (salt) a échoué : %s"), *CryptoHelper_GetOpenSSLError()));

	TArray<uint8> IV;
	if (!CryptoHelper_GenRandom(IV, GCM_IV_BYTES))
		return CryptoHelper_Err(FString::Printf(
			TEXT("RAND_bytes (IV) a échoué : %s"), *CryptoHelper_GetOpenSSLError()));

	TArray<uint8> Key;
	Key.SetNumZeroed(AES_KEY_BYTES);

	FTCHARToUTF8 PasswordUTF8(*Password);
	if (!CryptoHelper_PBKDF2(
		reinterpret_cast<const uint8*>(PasswordUTF8.Get()), PasswordUTF8.Length(),
		Salt.GetData(), PBKDF2_SALT_BYTES,
		Iterations, Key.GetData()))
	{
		FMemory::Memzero(Key.GetData(), AES_KEY_BYTES);
		return CryptoHelper_Err(FString::Printf(
			TEXT("PBKDF2_HMAC a échoué : %s"), *CryptoHelper_GetOpenSSLError()));
	}

	TArray<uint8> Ciphertext;
	uint8 Tag[GCM_TAG_BYTES];
	FMemory::Memzero(Tag, GCM_TAG_BYTES);

	if (!CryptoHelper_Encrypt(Key.GetData(), IV.GetData(), Plaintext, Ciphertext, Tag))
	{
		FMemory::Memzero(Key.GetData(), AES_KEY_BYTES);
		return CryptoHelper_Err(FString::Printf(
			TEXT("AES-256-GCM chiffrement a échoué : %s"), *CryptoHelper_GetOpenSSLError()));
	}

	FMemory::Memzero(Key.GetData(), AES_KEY_BYTES);

	TArray<uint8> Payload;
	Payload.Reserve(PBKDF2_SALT_BYTES + GCM_IV_BYTES + GCM_TAG_BYTES + Ciphertext.Num());
	Payload.Append(Salt);
	Payload.Append(IV);
	Payload.Append(Tag, GCM_TAG_BYTES);
	Payload.Append(Ciphertext);

	return CryptoHelper_Ok(MoveTemp(Payload));
}

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::EncryptBytes_AES256GCM_RawKey(
	const TArray<uint8>& Plaintext,
	const TArray<uint8>& RawKey32)
{
	using namespace OpenSSLCryptoConstants;
	CryptoHelper_ClearErrors();

	if (RawKey32.Num() != AES_KEY_BYTES)
		return CryptoHelper_Err(FString::Printf(
			TEXT("RawKey32 doit faire exactement %d octets (fourni : %d)."),
			AES_KEY_BYTES, RawKey32.Num()));

	TArray<uint8> IV;
	if (!CryptoHelper_GenRandom(IV, GCM_IV_BYTES))
		return CryptoHelper_Err(FString::Printf(
			TEXT("RAND_bytes (IV) a échoué : %s"), *CryptoHelper_GetOpenSSLError()));

	TArray<uint8> Ciphertext;
	uint8 Tag[GCM_TAG_BYTES];
	FMemory::Memzero(Tag, GCM_TAG_BYTES);

	if (!CryptoHelper_Encrypt(RawKey32.GetData(), IV.GetData(), Plaintext, Ciphertext, Tag))
		return CryptoHelper_Err(FString::Printf(
			TEXT("AES-256-GCM chiffrement a échoué : %s"), *CryptoHelper_GetOpenSSLError()));

	TArray<uint8> Payload;
	Payload.Reserve(GCM_IV_BYTES + GCM_TAG_BYTES + Ciphertext.Num());
	Payload.Append(IV);
	Payload.Append(Tag, GCM_TAG_BYTES);
	Payload.Append(Ciphertext);

	return CryptoHelper_Ok(MoveTemp(Payload));
}

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM(
	const TArray<uint8>& EncryptedPayload,
	const FString& Password,
	int32 Iterations)
{
	using namespace OpenSSLCryptoConstants;
	CryptoHelper_ClearErrors();

	if (Password.IsEmpty())
		return CryptoHelper_ErrLiteral(TEXT("Le mot de passe ne peut pas être vide."));

	if (Iterations < PBKDF2_MIN_ITERATIONS || Iterations > PBKDF2_MAX_ITERATIONS)
		return CryptoHelper_Err(FString::Printf(
			TEXT("Iterations invalide : doit être entre %d et %d."),
			PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS));

	if (EncryptedPayload.Num() < MIN_PASSWORD_PAYLOAD)
		return CryptoHelper_Err(FString::Printf(
			TEXT("Payload trop court : %d octets (minimum %d)."),
			EncryptedPayload.Num(), MIN_PASSWORD_PAYLOAD));

	const uint8* Ptr        = EncryptedPayload.GetData();
	const uint8* Salt       = Ptr; Ptr += PBKDF2_SALT_BYTES;
	const uint8* IV         = Ptr; Ptr += GCM_IV_BYTES;
	const uint8* Tag        = Ptr; Ptr += GCM_TAG_BYTES;
	const int32  CipherLen  = EncryptedPayload.Num() - MIN_PASSWORD_PAYLOAD;
	const uint8* Ciphertext = Ptr;

	TArray<uint8> Key;
	Key.SetNumZeroed(AES_KEY_BYTES);

	FTCHARToUTF8 PasswordUTF8(*Password);
	if (!CryptoHelper_PBKDF2(
		reinterpret_cast<const uint8*>(PasswordUTF8.Get()), PasswordUTF8.Length(),
		Salt, PBKDF2_SALT_BYTES,
		Iterations, Key.GetData()))
	{
		FMemory::Memzero(Key.GetData(), AES_KEY_BYTES);
		return CryptoHelper_Err(FString::Printf(
			TEXT("PBKDF2_HMAC a échoué : %s"), *CryptoHelper_GetOpenSSLError()));
	}

	TArray<uint8> Plaintext;
	if (!CryptoHelper_Decrypt(Key.GetData(), IV, Ciphertext, CipherLen, Tag, Plaintext))
	{
		FMemory::Memzero(Key.GetData(), AES_KEY_BYTES);
		return CryptoHelper_ErrLiteral(
			TEXT("Déchiffrement échoué : données corrompues, altérées ou mot de passe incorrect."));
	}

	FMemory::Memzero(Key.GetData(), AES_KEY_BYTES);
	return CryptoHelper_Ok(MoveTemp(Plaintext));
}

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::DecryptBytes_AES256GCM_RawKey(
	const TArray<uint8>& EncryptedPayload,
	const TArray<uint8>& RawKey32)
{
	using namespace OpenSSLCryptoConstants;
	CryptoHelper_ClearErrors();

	if (RawKey32.Num() != AES_KEY_BYTES)
		return CryptoHelper_Err(FString::Printf(
			TEXT("RawKey32 doit faire exactement %d octets (fourni : %d)."),
			AES_KEY_BYTES, RawKey32.Num()));

	if (EncryptedPayload.Num() < MIN_RAWKEY_PAYLOAD)
		return CryptoHelper_Err(FString::Printf(
			TEXT("Payload trop court : %d octets (minimum %d)."),
			EncryptedPayload.Num(), MIN_RAWKEY_PAYLOAD));

	const uint8* Ptr        = EncryptedPayload.GetData();
	const uint8* IV         = Ptr; Ptr += GCM_IV_BYTES;
	const uint8* Tag        = Ptr; Ptr += GCM_TAG_BYTES;
	const int32  CipherLen  = EncryptedPayload.Num() - MIN_RAWKEY_PAYLOAD;
	const uint8* Ciphertext = Ptr;

	TArray<uint8> Plaintext;
	if (!CryptoHelper_Decrypt(RawKey32.GetData(), IV, Ciphertext, CipherLen, Tag, Plaintext))
		return CryptoHelper_ErrLiteral(
			TEXT("Déchiffrement échoué : données corrompues, altérées ou clé incorrecte."));

	return CryptoHelper_Ok(MoveTemp(Plaintext));
}

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::DeriveKey_PBKDF2_HMACSHA256(
	const FString& Password,
	const TArray<uint8>& Salt,
	int32 Iterations,
	int32 KeyLengthBytes)
{
	using namespace OpenSSLCryptoConstants;
	CryptoHelper_ClearErrors();

	if (Password.IsEmpty())
		return CryptoHelper_ErrLiteral(TEXT("Le mot de passe ne peut pas être vide."));

	if (Salt.Num() == 0)
		return CryptoHelper_ErrLiteral(TEXT("Le salt ne peut pas être vide."));

	if (Iterations < PBKDF2_MIN_ITERATIONS || Iterations > PBKDF2_MAX_ITERATIONS)
		return CryptoHelper_Err(FString::Printf(
			TEXT("Iterations invalide : doit être entre %d et %d."),
			PBKDF2_MIN_ITERATIONS, PBKDF2_MAX_ITERATIONS));

	if (KeyLengthBytes <= 0 || KeyLengthBytes > 64)
		return CryptoHelper_ErrLiteral(TEXT("KeyLengthBytes invalide : doit être entre 1 et 64."));

	TArray<uint8> Key;
	Key.SetNumZeroed(KeyLengthBytes);

	FTCHARToUTF8 PasswordUTF8(*Password);
	if (PKCS5_PBKDF2_HMAC(
		reinterpret_cast<const char*>(PasswordUTF8.Get()),
		PasswordUTF8.Length(),
		Salt.GetData(), Salt.Num(),
		Iterations,
		EVP_sha256(),
		KeyLengthBytes,
		Key.GetData()) != 1)
	{
		FMemory::Memzero(Key.GetData(), KeyLengthBytes);
		return CryptoHelper_Err(FString::Printf(
			TEXT("PBKDF2_HMAC a échoué : %s"), *CryptoHelper_GetOpenSSLError()));
	}

	return CryptoHelper_Ok(MoveTemp(Key));
}

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::GenerateRandomBytes(int64 NumBytes)
{
	CryptoHelper_ClearErrors();

	// Validation TArray<uint8> est limite a INT32_MAX octets (env 2 Go)
	if (NumBytes <= 0)
	{
		return CryptoHelper_ErrLiteral(TEXT("NumBytes invalide : doit etre superieur a 0."));
	}
	if (NumBytes > OpenSSLCryptoConstants::RAND_MAX_BYTES)
	{
		const int64 MaxMB = OpenSSLCryptoConstants::RAND_MAX_BYTES / (1024LL * 1024LL);
		return CryptoHelper_Err(FString::Printf(
			TEXT("NumBytes invalide : %lld octets demandes, maximum %lld Mo (%lld octets)."),
			(long long)NumBytes,
			(long long)MaxMB,
			(long long)OpenSSLCryptoConstants::RAND_MAX_BYTES));
	}

	// Allouer le buffer (int32 cast sur car TArray utilise int32 en interne,
	// mais NumBytes <= INT32_MAX donc le cast est sans perte)
	TArray<uint8> Bytes;
	Bytes.SetNumUninitialized((int32)NumBytes);

	// RAND_bytes prend un int boucle par tranches de 16 Mo pour les grands buffers
	constexpr int32 CHUNK = 16 * 1024 * 1024; // 16 Mo par appel
	int64 Remaining = NumBytes;
	int64 Offset    = 0;
	while (Remaining > 0)
	{
		const int32 Step = (int32)FMath::Min((int64)CHUNK, Remaining);
		if (RAND_bytes(Bytes.GetData() + Offset, Step) != 1)
		{
			return CryptoHelper_Err(FString::Printf(
				TEXT("RAND_bytes a echoue a l'offset %lld Mo : %s"),
				(long long)(Offset / (1024LL * 1024LL)),
				*CryptoHelper_GetOpenSSLError()));
		}
		Offset    += Step;
		Remaining -= Step;
	}

	return CryptoHelper_Ok(MoveTemp(Bytes));
}

FString UOpenSSLCryptoBPLibrary::BytesToHexString(const TArray<uint8>& Bytes)
{
	FString Result;
	Result.Reserve(Bytes.Num() * 2);
	for (uint8 B : Bytes)
	{
		Result += FString::Printf(TEXT("%02X"), B);
	}
	return Result;
}

FOpenSSLCryptoResult UOpenSSLCryptoBPLibrary::HexStringToBytes(const FString& HexString)
{
	if (HexString.Len() % 2 != 0)
		return CryptoHelper_ErrLiteral(
			TEXT("La chaîne hexadécimale doit avoir un nombre pair de caractères."));

	TArray<uint8> Bytes;
	Bytes.SetNumUninitialized(HexString.Len() / 2);

	for (int32 i = 0; i < Bytes.Num(); ++i)
	{
		FString ByteStr = HexString.Mid(i * 2, 2);
		const TCHAR C0 = ByteStr[0];
		const TCHAR C1 = ByteStr[1];

		auto HexVal = [](TCHAR C) -> int32
		{
			if (C >= TEXT('0') && C <= TEXT('9')) return C - TEXT('0');
			if (C >= TEXT('A') && C <= TEXT('F')) return C - TEXT('A') + 10;
			if (C >= TEXT('a') && C <= TEXT('f')) return C - TEXT('a') + 10;
			return -1;
		};

		int32 Hi = HexVal(C0);
		int32 Lo = HexVal(C1);

		if (Hi < 0 || Lo < 0)
			return CryptoHelper_Err(FString::Printf(
				TEXT("Caractère hexadécimal invalide à la position %d."), i * 2));

		Bytes[i] = static_cast<uint8>((Hi << 4) | Lo);
	}

	return CryptoHelper_Ok(MoveTemp(Bytes));
}

TArray<uint8> UOpenSSLCryptoBPLibrary::StringToUTF8Bytes(const FString& Text)
{
	FTCHARToUTF8 UTF8(*Text);
	TArray<uint8> Bytes;
	Bytes.Append(reinterpret_cast<const uint8*>(UTF8.Get()), UTF8.Length());
	return Bytes;
}

FString UOpenSSLCryptoBPLibrary::UTF8BytesToString(const TArray<uint8>& Bytes)
{
	if (Bytes.Num() == 0) { return FString(); }

	TArray<uint8> Temp = Bytes;
	Temp.Add(0);

	FUTF8ToTCHAR Converted(reinterpret_cast<const ANSICHAR*>(Temp.GetData()));
	return FString(Converted.Get());
}
