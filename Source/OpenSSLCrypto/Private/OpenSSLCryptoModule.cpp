// OpenSSLCryptoModule.cpp

#include "OpenSSLCryptoModule.h"
#include "Modules/ModuleManager.h"

#define LOCTEXT_NAMESPACE "FOpenSSLCryptoModule"

void FOpenSSLCryptoModule::StartupModule()
{
	// Rien à initialiser — OpenSSL est initialisé par le module UE "OpenSSL"
	// qui est chargé avant nous (dépendance déclarée dans Build.cs)
}

void FOpenSSLCryptoModule::ShutdownModule()
{
	// Rien à nettoyer
}

#undef LOCTEXT_NAMESPACE

IMPLEMENT_MODULE(FOpenSSLCryptoModule, OpenSSLCrypto)
