#pragma once
#ifndef __CRYPT_H__
#define __CRYPT_H__

#include <wincrypt.h>

// Client part.
HCRYPTKEY hKeyPair; // Дескриптор ассимитричной пары ключей.
BYTE *pbKeyPublicBlob; // Открытый ключ в виде массива байт.
DWORD dwPublicBlobLen; // Длина открытого ключа в байтах.
HCRYPTKEY hSessionKey; // Дескриптор сессионного ключа.

int cryptClientInit();
int cryptClientImportSessionKey(BYTE *encyptedSessionKey, DWORD encyptedSessionKeyLen);

int cryptServerInit();
int cryptServerGenSessionKey(HCRYPTKEY *hSessionKey, BYTE *publicClientKey, DWORD publicClientKeyLen, BYTE **encryptedSessionKey, DWORD *encryptedSessionKeyLen);

#define encryptBufferLen 1024 * 1024
char encryptBuffer[encryptBufferLen]; // Общий буфер для записи текста, его шифровки и отправки.
int encryptLength;

#define decryptBufferLen 1024 * 1024
char decryptBuffer[decryptBufferLen]; // Общий буфер для записи текста, его расшифровки.
int decryptLength;

int encrypt(HCRYPTKEY hKey, char *str);
int decrypt(HCRYPTKEY hKey, char *data, size_t length);

#endif