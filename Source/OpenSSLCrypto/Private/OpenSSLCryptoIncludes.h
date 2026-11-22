#pragma once

// OpenSSLCryptoIncludes.h
//
// Analyse du ui.h réel de UE5.5 (OpenSSL 1.1.1t, Win64/VS2015) :
//
//   Ligne 10 : #ifndef HEADER_UI_H = include-guard exacte
//   Ligne 11 : #define HEADER_UI_H
//   Ligne 20 : #include <openssl/ossl_typ.h> = C'est ICI que "typedef struct ui_st UI" est défini
//
// Le type UI est déclaré dans ossl_typ.h, pas dans ui.h directement.
// ui.h l'utilise ensuite (UI *UI_new(), etc).
//
// STRATÉGIE :
//   1. Poser HEADER_UI_H avant tout include OpenSSL → ui.h est skipé entièrement.
//   2. ossl_typ.h sera inclus normalement par evp.h, mais il contient le
//      typedef UI On bloque ce typedef avec OPENSSL_OSSL_TYP_H_DUMMY_UI
//      (non standard) ou plus simplement, on laisse ossl_typ.h s'inclure
//      et on force un #define UI qui le remplace avant que Slate ne déclare
//      namespace UI
//
// SOLUTION DÉFINITIVE :
//   La seule façon garantie de supprimer le conflit typedef vs namespace
//   sans patcher les headers OpenSSL est de définir une macro UI AVANT
//   l'inclusion de tout header OpenSSL, de façon à ce que le préprocesseur
//   remplace "typedef struct ui_st UI" par "typedef struct ui_st <macro_value>"
//
//   On utilise : #define UI OpenSSL_UI
//   Cela redirige le typedef → "typedef struct ui_st OpenSSL_UI"
//   Le nom "UI" reste libre pour Slate/UMG
//   Les fonctions de ui.h (UI_new etc.) ne nous intéressent pas
//   on bloque ui.h avec HEADER_UI_H de toute façon

// Étape 1 : Rediriger le typedef UI → OpenSSL_UI dans ossl_typ.h
//   DOIT être défini avant tout include OpenSSL
#ifndef UI
#define UI OpenSSL_UI
#endif

THIRD_PARTY_INCLUDES_START

// Étape 2 : Bloquer ui.h entièrement (include-guard exacte du fichier réel)
//   ui.h utilise UI* partout si on le bloque, pas de collision de fonctions
//   On n'a pas besoin de UI_new(), UI_free() etc. dans ce plugin
#ifndef HEADER_UI_H
#define HEADER_UI_H
#endif

// Étape 3 : Inclure les headers OpenSSL dont on a besoin
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

THIRD_PARTY_INCLUDES_END

// Étape 4 : Supprimer la macro UI maintenant que les includes OpenSSL sont terminés.
//   Slate/UMG pourra déclarer "namespace UI" sans interférence
#ifdef UI
#undef UI
#endif
