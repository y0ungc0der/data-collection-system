#pragma once
#ifndef __SYSTEM_H__
#define __SYSTEM_H__

#include <winsock2.h>
#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <locale.h>
#include <math.h>

#include <aclapi.h>
#include <sddl.h>

#pragma warning(disable : 4996) // Для отключения сообщений об устаревших и небезопасных функциях

void debugging();

const char *getOsVersionName();
const char *getCurrentTime();
const char *getTimeSinceStart();
const char *getMemoryInfo();
const char *getDrivesList();
const char *getLogicalDrivesMemoryInfo();
const char *getOwner(char *path, SE_OBJECT_TYPE se);
const char *getAccessRights(char *path, SE_OBJECT_TYPE se);

char * scan_line(char *line);

#endif