#include "client.h"

int init()
{
	// Для Windows следует вызвать WSAStartup перед началом использования сокетов
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
}

void deinit()
{
	// Для Windows следует вызвать WSACleanup в конце работы
	WSACleanup();
}

int sock_err(const char * function, int s)
{
	int err;
	err = WSAGetLastError();
	fprintf(stderr, "%s: socket error: %d\n", function, err);
	return -1;
}

int send_raw_data(int s, const char *request, unsigned size)
{
	unsigned int sent = 0;

	while (sent < size)
	{
		// Отправка очередного блока данных.
		int res = send(s, request + sent, size - sent, 0);
		if (res < 0) return sock_err("send #1", s);
		sent += res;
		printf("%d bytes sent.\n", sent);
	}

	int res = send(s, "\0", 1, 0);
	if (res < 0) return sock_err("send #2", s);

	return 0;
}

/* Отправляет запрос на удаленный сервер. */
int send_request(int s, const char *request)
{
	return send_raw_data(s, request, strlen(request));
}

/* Получение данных в буфер buf, размер которого buf_len. */
int recv_response(int s, char *buf, int buf_len)
{
	int r, total_r = 0;

	struct timeval tv;
	fd_set rfd;

	memset(buf, 0, buf_len);
	while ((r = recv(s, buf + total_r, buf_len - total_r, 0)) > 0)
	{
		total_r += r;

		tv.tv_sec = 0;
		tv.tv_usec = 200 * 1000;
		FD_ZERO(&rfd);
		FD_SET(s, &rfd);

		if (select(s + 1, &rfd, NULL, 0, &tv) <= 0) break;
	}

	if (r < 0) return sock_err("recv error", s);
	//else if (r == 0) return sock_err("unexpected connection closing", s);

	// Проверка, что пришел символ \0.
	for (int i = total_r - 1; i > 0; i--)
		if (buf[i] == '\0') return i;

	return total_r;
}

// Функция определяет IP-адрес узла по его имени.
// Адрес возвращается в сетевом порядке байтов.
unsigned int get_host_ipn(const char *name)
{
	struct addrinfo * addr = 0;
	unsigned int ip4addr = 0;

	// Функция возвращает все адреса указанного хоста.
	// в виде динамического однонаправленного списка.
	if (0 == getaddrinfo(name, 0, 0, &addr))
	{
		struct addrinfo * cur = addr;
		while (cur)
		{
			// Интересует только IPv4 адрес, если их несколько - то первый.
			if (cur->ai_family == AF_INET)
			{
				ip4addr = ((struct sockaddr_in *) cur->ai_addr)->sin_addr.s_addr;
				break;
			}
			cur = cur->ai_next;
		}
		freeaddrinfo(addr);
	}

	return ip4addr;
}

char result[256];
char * chooseMenu()
{	
	char tmp[256];
	while (1)
	{
		memset(result, 0, sizeof(result));

		printf("Please, choose info:\n");
		printf(" 0 - OS info\n");
		printf(" 1 - current time\n");
		printf(" 2 - time since OS launch\n");
		printf(" 3 - memory info\n");
		printf(" 4 - disks info\n");
		printf(" 5 - free disk space\n");
		printf(" 6 - access rigths\n");
		printf(" 7 - get object's owner\n");
		printf("Your choice: ");
		int t = scan_line(result)[0];
		if (t < '0' || t > '7')
		{
			printf("Wrong choice :(\n");
			system("pause & cls");
			continue;
		}

		if (t == '6' || t == '7')
		{
			printf(" Enter path to FILE or REGISTRY OBJECT: ");
			scan_line(result + 2);

			printf(" Enter type of object (f or r): ");
			t = scan_line(tmp)[0];
			if (t != 'f' && t != 'r')
			{
				printf("No no no..\n");
				system("pause & cls");
				continue;
			}
			*(result + 1) = t;
			*(result + strlen(result)) = '\0';
		}

		return result;
	}
}

int client(char *host, int port)
{
	printf("\nRunning the client...\n");

	int s;
	struct sockaddr_in addr;

	// Инициалиазация сетевой библиотеки
	if (!init())
		return sock_err("WSAStartup error", -1);

	// Создание TCP-сокета
	s = socket(AF_INET, SOCK_STREAM, 0);
	if (s < 0)
		return sock_err("socket", s);

	// Заполнение структуры с адресом удаленного узла
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = get_host_ipn(host);

	// Если подключится не удалось.
	if (connect(s, (struct sockaddr*) &addr, sizeof(addr)) != 0)
	{
		closesocket(s);
		return sock_err("connect", s);
	}

	printf("Connected.\n");
	
	// Работа по установке зашифрованного соединения.
	{
		// Генерируем пару ключей публичный/приватный, отправляем публичный ключ на сервер.
		if (cryptClientInit())
			return sock_err("Error while initializing client's key pair!", s);
		else
			printf("A pair of keys has been created.\n");

		// Отправляем открытый ключ.
		send_raw_data(s, pbKeyPublicBlob, dwPublicBlobLen);
		free(pbKeyPublicBlob);
		pbKeyPublicBlob = NULL;

		// Принимаем шифрованный сессионный ключ, расшифровываем его с помощью приватного ключа.
		BYTE encyptedSessionKey[4096]; // Шифрованный сессионный ключ.
		DWORD encyptedSessionKeyLen; // Его длина.
		memset(encyptedSessionKey, 0, sizeof(encyptedSessionKey));
		encyptedSessionKeyLen = recv_response(s, encyptedSessionKey, sizeof(encyptedSessionKey));

		cryptClientImportSessionKey(encyptedSessionKey, encyptedSessionKeyLen);
		printf("Successfully got session key, length %d.\n", encyptedSessionKeyLen);
	}

	char *type;
	while (1)
	{
		system("pause & cls");
		type = chooseMenu();

		encrypt(hSessionKey, type);
		send_raw_data(s, encryptBuffer, encryptLength);

		decryptLength = recv_response(s, decryptBuffer, decryptBufferLen);
		decrypt(hSessionKey, decryptBuffer, decryptLength);

		printf("\n%s\n", decryptBuffer);
	}

	return 0;
}