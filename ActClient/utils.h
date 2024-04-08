#pragma once
#include <iostream>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>

#define MAX_IPV4_SIZE 16

namespace GeneralUtils {
	int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString);
	int WcharpToCharp(char* ConvertString, const WCHAR* ConvertedString);
	int GetNumFromString(char Str[]);
	void ResetString(char Str[]);
	void WideResetString(WCHAR Str[]);
	BOOL ValidateFileReqPath(char FilePath[], char Type);
	char ReturnInput(const char* PrintfStr);
	DWORD CountOccurrences(const char* SearchStr, char SearchLetter);
	int FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData, ULONG64* FileDataSize, BOOL IsWrite);
	ULONG CalculateAddressValue(char* IpAddress);
	BOOL CalculateAddressString(char* IpAddress, ULONG AddressValue);
}
namespace IpAddresses {
	BOOL IsValidIp(char* Address);
	DWORD CompareIpAddresses(char* LocalHost, char* RemoteAddr);
	BOOL MatchIpAddresses(char* AttackerAddress, char* TargetAddress);
}