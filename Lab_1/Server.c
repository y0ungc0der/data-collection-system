#include "server.h"

struct client_ctx
{
	int socket;
	CHAR buf_recv[4096]; // Буфер приема
	CHAR buf_send[4096]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено

	// Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	DWORD flags_recv; // Флаги для WSARecv

	CHAR disconnect_reason[32];
	HCRYPTKEY hSessionKey; // Дескриптор сеансового ключа.
	BOOL secureEstablished; // Флаг устанвки шифрованного соединения.
};

// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx g_ctxs[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;

// Сообщение об ошибке
static int sock_err(const char *err)
{
	printf("!!! ERROR !!! %s: %x\n", err, GetLastError());
	system("pause");
	return -1;
}

// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = g_ctxs[idx].buf_recv + g_ctxs[idx].sz_recv;
	buf.len = sizeof(g_ctxs[idx].buf_recv) - g_ctxs[idx].sz_recv;
	memset(&g_ctxs[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	g_ctxs[idx].flags_recv = 0;
	WSARecv(g_ctxs[idx].socket, &buf, 1, NULL, &g_ctxs[idx].flags_recv, &g_ctxs[idx].overlap_recv, NULL);
}

// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	WSABUF buf; buf.buf = g_ctxs[idx].buf_send + g_ctxs[idx].sz_send; buf.len = g_ctxs[idx].sz_send_total - g_ctxs[idx].sz_send;
	memset(&g_ctxs[idx].overlap_send, 0, sizeof(OVERLAPPED));
	WSASend(g_ctxs[idx].socket, &buf, 1, NULL, 0, &g_ctxs[idx].overlap_send, NULL);
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве g_ctxs для вставки нового подключения
	for (i = 0; i < sizeof(g_ctxs) / sizeof(g_ctxs[0]); i++)
	{
		if (g_ctxs[i].socket == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(g_ctxs[0].buf_recv, g_ctxs[0].sz_recv, sizeof(struct sockaddr_in) + 16,
				sizeof(struct sockaddr_in) + 16, (struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **) &remote_addr,
				&remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff,
				(ip >> 8) & 0xff, (ip) & 0xff);
			g_ctxs[i].socket = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)g_ctxs[i].socket, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}

// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&g_ctxs[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление.
	// Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(g_ctxs[0].socket, g_accepted_socket, g_ctxs[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &g_ctxs[0].overlap_recv);
}

int is_string_received(DWORD idx, int *len)
{
	DWORD i;

	//printf("got: %d\n", g_ctxs[idx].sz_recv);
	if (g_ctxs[idx].buf_recv[g_ctxs[idx].sz_recv - 1] == '\0')
	{
		*len = (int) g_ctxs[idx].sz_recv - 1;
		return 1;
	}

	*len = g_ctxs[idx].sz_recv;
	return 0;
}

void send_data(DWORD idx, BYTE *buf, size_t len)
{
	memset(g_ctxs[idx].buf_send, 0, sizeof(g_ctxs[idx].buf_send));
	memcpy(g_ctxs[idx].buf_send, buf, len);
	g_ctxs[idx].sz_send_total = len + 1; // + 1 для отправки \0.
	g_ctxs[idx].sz_send = 0;
	schedule_write(idx);
}

void send_string(DWORD idx, char *buf)
{
	sprintf(g_ctxs[idx].buf_send, buf, strlen(buf));
	g_ctxs[idx].sz_send_total = strlen(g_ctxs[idx].buf_send) + 1; // + 1 для отправки \0.
	g_ctxs[idx].sz_send = 0;
	schedule_write(idx);
}

// Функция закрывает соединение.
void schedule_close(DWORD idx, const char *reason)
{
	sprintf(g_ctxs[idx].disconnect_reason, reason);
	CancelIo((HANDLE)g_ctxs[idx].socket);
	PostQueuedCompletionStatus(g_io_port, 0, idx, &g_ctxs[idx].overlap_cancel);
}

int protocol_check(ULONG_PTR key)
{
	if (g_ctxs[key].sz_recv == 0) return 0;
	
	int len; // Длина принятых данных.
	if (!is_string_received(key, &len))
//	{ printf("RECEIVED ONLY: %d %s\n", len, g_ctxs[key].buf_recv);
		return 0;
//	} else printf("STRING FULLY RECEIVED: %d %s\n", len, g_ctxs[key].buf_recv);

	// Определяем открытый ключ, если он еще не установлен.
	if (g_ctxs[key].secureEstablished == FALSE)
	{
		BYTE publicClientKey[512]; // Буфер для открытого ключа.
		DWORD publicClientKeyLen; // Его длина.

		// Сохраняем открытый ключ.
		publicClientKeyLen = len;
		memcpy(publicClientKey, g_ctxs[key].buf_recv, publicClientKeyLen);
		printf("  got a public key from %d, length: %d\n", key, publicClientKeyLen);

		// Очищаем буфер приема.
		memset(g_ctxs[key].buf_recv, 0, sizeof(g_ctxs[key].buf_recv));
		g_ctxs[key].sz_recv = 0;

		// Генерируем сессионный ключ и шифруем его, пишем его в буфер и отправляем клиенту.
		BYTE *encryptedSessionKey;
		DWORD encryptedSessionKeyLen;
		if (cryptServerGenSessionKey(&g_ctxs[key].hSessionKey, publicClientKey, publicClientKeyLen, &encryptedSessionKey, &encryptedSessionKeyLen))
			return sock_err("Error while generating session key");
		else
			printf("  a session key for %d has been created\n", key);
		printf("key len: %d\n", encryptedSessionKeyLen);

		send_data(key, encryptedSessionKey, encryptedSessionKeyLen);

		g_ctxs[key].secureEstablished = TRUE;
		printf("  encrypted connection with %d established\n", key);

		return 0;
	}

	memcpy(decryptBuffer, g_ctxs[key].buf_recv, len);
	memset(g_ctxs[key].buf_recv, 0, sizeof(g_ctxs[key].buf_recv)); // Очищаем буфер приема.
	g_ctxs[key].sz_recv = 0;
	decrypt(g_ctxs[key].hSessionKey, decryptBuffer, len);

	printf("got request from %d: %s\n", key, decryptBuffer);

	char *data;
	char ctype = decryptBuffer[0];
	switch (ctype)
	{
		case '0':
			data = getOsVersionName();
			break;
		case '1':
			data = getCurrentTime();
			break;
		case '2':
			data = getTimeSinceStart();
			break;
		case '3':
			data = getMemoryInfo();
			break;
		case '4':
			data = getDrivesList();
			break;
		case '5':
			data = getLogicalDrivesMemoryInfo();
			break;
		case '6':
		{
			char type = decryptBuffer[1]; // Тип: f - файл, r - ключ реестра.
			char *path = decryptBuffer + 2; // Строка с путем к файлу\ключу реестра.

			SE_OBJECT_TYPE ot = (type == 'r') ? SE_REGISTRY_KEY : SE_FILE_OBJECT;

			//printf("type: %c\npath: %s\not: %d\n", type, path, ot);

			data = getAccessRights(path, ot);
			//printf("%s\n", data);
			if (data == NULL) data = "Get security information error";
			break;
		}
		case '7':
		{
			char type = decryptBuffer[1]; // Тип: f - файл, r - ключ реестра.
			char *path = decryptBuffer + 2; // Строка с путем к файлу\ключу реестра.

			SE_OBJECT_TYPE ot = (type == 'r') ? SE_REGISTRY_KEY : SE_FILE_OBJECT;
			data = getOwner(path, ot);
			if (data == NULL) data = "Get security information error";
			break;
		}
		default:
		{
			printf("[WARNING] unknown type: %c\n", ctype);
			data = "unknown";
		}
	}

	encrypt(g_ctxs[key].hSessionKey, data);
	send_data(key, encryptBuffer, encryptLength);
	
	return 0;
}

int io_serv(int port)
{
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
		printf("WSAStartup ok\n");
	else
		printf("WSAStartup error\n");
	
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	// AF_INET - Семейство адресов Интернет - протокола версии 4 (IPv4).
	// SOCK_STREAM - Тип сокета использует протокол управления передачей(TCP).
	// WSA_FLAG_OVERLAPPED - Сокет, который поддерживает перекрывающиеся операции ввода-вывода.
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return 0;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(g_ctxs, 0, sizeof(g_ctxs));
	memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons(port);
	// Функция bind связывает локальный адрес с сокетом.
	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0) { printf("error bind() or listen()\n"); return -1; }
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return -1;
	}

	// Инициализация сервера для работы с шифрованием
	cryptServerInit();

	g_ctxs[0].socket = s;
	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				g_ctxs[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			} else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве g_ctxs
				if (&g_ctxs[key].overlap_recv == lp_overlap)
				{
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						schedule_close(key, "by client");
						continue;
					}

					g_ctxs[key].sz_recv += transferred;
					
					if (protocol_check(key)) // Проверка на соответствие протоколу, установление соединения.
						// Пришли данные. Первое, что должно придти - открытый ключ.
						schedule_close(key, "protocol error #1");
					else // Иначе - ждем данные дальше
						schedule_read(key);

				} else if (&g_ctxs[key].overlap_send == lp_overlap)
				{
					// Данные отправлены
					g_ctxs[key].sz_send += transferred;
					if (g_ctxs[key].sz_send < g_ctxs[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					} else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						// schedule_close(key, "transmit complete");
					}
				} else if (&g_ctxs[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(g_ctxs[key].socket);
					memset(&g_ctxs[key], 0, sizeof(g_ctxs[key]));
					printf(" connection %u closed\n", key);
				}
			}
		} else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
		}
	}

	return 0;
}