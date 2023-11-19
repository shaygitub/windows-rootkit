#pragma once
#include <iostream>
#include <Windows.h>
#include <random>


// Class used to write log files -
class LogFile {
public:
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    char* FilePath = NULL;

    DWORD InitiateFile(const char* Name) {
        FilePath = (char*)malloc(strlen(Name) + 1);
        if (FilePath == NULL) {
            return GetLastError();
        }
        memcpy(FilePath, Name, strlen(Name) + 1);

        FileHandle = CreateFileA(Name, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (FileHandle == INVALID_HANDLE_VALUE) {
            free(FilePath);
            return GetLastError();
        }
        return 0;
    }

    DWORD WriteLog(PVOID Buffer, DWORD Size) {
        DWORD Written = 0;
        if (!WriteFile(FileHandle, Buffer, Size, &Written, NULL) || Written != Size) {
            if (FilePath != NULL) {
                free(FilePath);
            }
            if (FileHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(FileHandle);
            }
            return GetLastError();
        }
        return 0;
    }

    void WriteError(const char* Message, DWORD Value) {
        char ValueStr[100] = { 0 };
        char Backs = '\n';

        if (WriteLog((PVOID)Message, (DWORD)strlen(Message) + 1) == 0) {
            _itoa_s((int)Value, ValueStr, 10);
            if (WriteLog((PVOID)ValueStr, (DWORD)strlen(ValueStr) + 1) == 0) {
                WriteLog(&Backs, 1);
            }
        }
        if (FilePath != NULL) {
            free(FilePath);
        }
        if (FileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(FileHandle);
        }
    }

    void CloseLog() {
        if (FilePath != NULL) {
            free(FilePath);
        }
        if (FileHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(FileHandle);
        }
    }
};


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