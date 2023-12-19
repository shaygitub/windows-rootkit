#pragma once
#include "medium.h"


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
    
    void RenewLog() {
        FileHandle = CreateFileA(FilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
};


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
std::uint32_t GetPID(std::string PrcName);  // Get the PID of a running process, NULL if does not exist/not currently running
BOOL ValidateInfoTypeString(const char* InfoType);  // Check for valid info type string (RKOP_SYSINFO)