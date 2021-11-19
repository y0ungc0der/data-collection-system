#include "system.h"
#include "crypt.h"

#define error(x) { printf("[ERROR] %s\n", x); return -1; }

HCRYPTPROV hProv; // Дескриптор криптопровайдера.
CHAR *containerName = "MegaSecureContainer"; // Название контейнера ключей.

// ================================================================================

/* Инициализация клиента для работы с шифрованием, генерация публичного ключа... */
int cryptClientInit()
{
	// Создание криптоконтейнера.
	// Имя используемого CSP: MS_DEF_PROV - Microsoft Base Cryptographic Provider
	// Тип провайдера PROV_RSA_FULL: обмен ключами - RSA; шифрование RC2/RC4
	// CRYPT_NEWKEYSET - создает новый контейнер ключей с именем, указанным pszContainer.Если pszContainer имеет значение NULL, создается контейнер ключей с именем по умолчанию.
	if (!CryptAcquireContext(&hProv, containerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET)){
		// Тут ошибка, удаляем и пытаемся снова.
		// CRYPT_DELETEKEYSET - Удалить контейнер ключей
		CryptAcquireContext(&hProv, containerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		if (!CryptAcquireContext(&hProv, containerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			error("Create key container error!");
	}

	// Генерация пары ассиметричных ключей. AT_KEYEXCHANGE - для обмена ключами. CRYPT_EXPORTABLE - ключ можно будет экспортировать. 
	if (!CryptGenKey(hProv, AT_KEYEXCHANGE, CRYPT_EXPORTABLE, &hKeyPair))
		error("Error during CryptGenKey!");

	// Определение длины открытого ключа. PUBLICKEYBLOB - работаем с открытым ключом.
	// Чтобы получить требуемый размер буфера pbKeyPublicBlob, передайте NULL для pbKeyPublicBlob.\
	   Требуемый размер буфера будет помещен в значение, указанное параметром dwPublicBlobLen.
	// Приложения должны использовать фактический размер возвращаемых данных.\
	На входе размеры буфера обычно задаются достаточно большими.\
	На выходе переменная, на которую указывает этот параметр, обновляется, чтобы отразить фактический размер данных, скопированных в буфер.
	if (!CryptExportKey(hKeyPair, 0, PUBLICKEYBLOB, NULL, NULL, &dwPublicBlobLen))
		error("Public BLOB size error.");

	// Выделяет память для pbKeyPublicBlob
	pbKeyPublicBlob = (BYTE *) malloc(dwPublicBlobLen);
	if (pbKeyPublicBlob == NULL) error("malloc error!");

	// Фактический экспорт публичного ключа в буфер защищенным образом.
	if (!CryptExportKey(hKeyPair, 0, PUBLICKEYBLOB, NULL, pbKeyPublicBlob, &dwPublicBlobLen))
		error("Public key couldn't be written in BLOB.");

	return 0;
}

/* Расшифровывает полученный зашифрованный сессионный ключ закрытым ключом и присваивает ему дескриптор #hSessionKey. */
int cryptClientImportSessionKey(BYTE *encyptedSessionKey, DWORD encyptedSessionKeyLen)
{
	CryptImportKey(hProv, encyptedSessionKey, encyptedSessionKeyLen, hKeyPair, NULL, &hSessionKey);
}

// ================================================================================

/* Инициализация сервера для работы с шифрованием. */
int cryptServerInit()
{
	// Создание криптоконтейнера.
	// Имя используемого CSP: MS_DEF_PROV - Microsoft Base Cryptographic Provider
	// Тип провайдера PROV_RSA_FULL: обмен ключами - RSA; шифрование RC2/RC4
	// CRYPT_NEWKEYSET - создает новый контейнер ключей с именем, указанным pszContainer.Если pszContainer имеет значение NULL, создается контейнер ключей с именем по умолчанию.
	if (!CryptAcquireContext(&hProv, containerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
	{
		// Тут ошибка, удаляем и пытаемся снова.
		// CRYPT_DELETEKEYSET - Удалить контейнер ключей
		CryptAcquireContext(&hProv, containerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_DELETEKEYSET);
		if (!CryptAcquireContext(&hProv, containerName, MS_DEF_PROV, PROV_RSA_FULL, CRYPT_NEWKEYSET))
			error("Create key container error!");
	}
}

int cryptServerGenSessionKey(HCRYPTKEY *hSessionKey, BYTE *publicClientKey, DWORD publicClientKeyLen, BYTE **encryptedSessionKey, DWORD *encryptedSessionKeyLen)
{
	// Генерация сеансового ключа.
	// CALG_RC4	- Алгоритм потокового шифрования RC4
	if (!CryptGenKey(hProv, CALG_RC4, CRYPT_EXPORTABLE, hSessionKey))
		error("Error during CryptGenKey!");

	// Кладем полученый открытый ключ в криптоконтейнер, получаем его дескриптор.
	HCRYPTKEY hKeyPublic;
	CryptImportKey(hProv, publicClientKey, publicClientKeyLen, NULL, NULL, &hKeyPublic);

	// Шифруем сессионый ключ открытым ключом для отправки клиенту.
	{
		// Определяем длину шифрованного ключа.
		// SIMPLEBLOB -	Используется для транспортировки ключей сеанса.
		// hExpKey -Дескриптор открытого ключа. Данные ключа в экспортирующемся ключе BLOB зашифрованы с использованием этого ключа.
		if (!CryptExportKey(*hSessionKey, hKeyPublic, SIMPLEBLOB, NULL, NULL, encryptedSessionKeyLen))
			error("Session BLOB size error!");

		// Выделяем память и получаем шифрованный сессионный ключ.
		*encryptedSessionKey = (BYTE *) malloc(*encryptedSessionKeyLen);
		if (*encryptedSessionKey == NULL) error("malloc error!");
		if (!CryptExportKey(*hSessionKey, hKeyPublic, SIMPLEBLOB, NULL, *encryptedSessionKey, encryptedSessionKeyLen))
			error("Session key couldn't be written in BLOB!");
	}

	return 0;
}

// ================================================================================

// Шифруем строку str сессионным ключом hKey.
int encrypt(HCRYPTKEY hKey, char *str)
{
	if (str == NULL)
	{
		encryptLength = 0;
		encryptBuffer[0] = '\0';
		return;
	}

	encryptLength = strlen(str);
	sprintf(encryptBuffer, "%s", str);

	// Функция CryptEncrypt шифрует данные.\
	   Алгоритм, используемый для шифрования данных, обозначается ключом, хранящимся в модуле CSP, и на него ссылается параметр hKey .
	if (!CryptEncrypt(hKey, NULL, TRUE, NULL, encryptBuffer, &encryptLength, encryptBufferLen))
		return printf("  error while encrypting data\n");
	else
		return encryptLength;
}

// Расшифрование данных.
int decrypt(HCRYPTKEY hKey, char *data, size_t length)
{
	if (data == NULL || length == 0)
	{
		decryptLength = 0;
		decryptBuffer[0] = '\0';
		return;
	}

	decryptLength = length;
	memcpy(decryptBuffer, data, length);

	// Функция CryptDecrypt расшифровывает данные, ранее зашифрованные с помощью функции CryptEncrypt.
	if (!CryptDecrypt(hKey, NULL, TRUE, NULL, decryptBuffer, &decryptLength))
		return printf("  error while decrypting data!\n");
	else
	{
		decryptBuffer[decryptLength] = '\0';
		return decryptLength;
	}
}