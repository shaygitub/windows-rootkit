#pragma once
#include <iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>

#define MAX_IPV4_SIZE 16

char ReturnInput(const char* PrintfStr);
DWORD CountOccurrences(const char* SearchStr, char SearchLetter);
BOOL CheckForValidIp(char* Address);
DWORD CompareIpAddresses(char* LocalHost, char* RemoteAddr);
BOOL MatchIpAddresses(char* AttackerAddress, char* TargetAddress);