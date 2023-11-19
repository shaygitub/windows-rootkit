#pragma once
#define MAXIPV4_ADDRESS_SIZE 16  // 3 * 4 triple digit numbers + 3 dots + null terminator
#define MAX_PORT_SIZE 6  // 5 + null terminator
#define MAX_DEBUGKEY_SIZE 56  // 4 * up to 13 character chunks + 3 dots + null terminator

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <string>
#include <WinSock2.h>
#include <Windows.h>
#pragma comment(lib, "Ws2_32.lib")

DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr);
BOOL MatchIpAddresses(char* TargetAddress, char* AttackerAddress, const char* AttackerIps);