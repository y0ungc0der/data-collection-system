#pragma once
#ifndef __SERVER_H__
#define __SERVER_H__

#define _WINSOCKAPI_
#define WIN32_LEAN_AND_MEAN
#define MAX_CLIENTS (100)

#include <windows.h>
#include <winsock2.h>
#include <mswsock.h>

#include <stdio.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

#include <wincrypt.h>

#include <stdlib.h>
#include <string.h>
#include <conio.h> 
#include <aclapi.h>
#include <math.h>
#include <time.h>

#include "crypt.h"
#include "system.h"

int io_serv(int port);

#pragma warning(disable : 4996) // Для отключения сообщений об устаревших и небезопасных функциях

#endif