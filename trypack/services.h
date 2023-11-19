#pragma once
#include <Windows.h>
#include <iostream>
#include <Winternl.h>
#include <string>
#include <fstream>
#pragma warning( disable : 4267)
#pragma warning( disable : 4244)
#pragma comment(lib, "ntdll.lib")
using LoadServiceDriver = NTSTATUS(__fastcall*)(PUNICODE_STRING);  // definition of NtLoadDriver function (used for converting pointer and calling)
using UnloadServiceDriver = NTSTATUS(__fastcall*)(PUNICODE_STRING);  // definition of NtUnloadDriver function (used for converting pointer and calling)


class RootService {
private:
    char ServiceFile[MAX_PATH] = { 0 };
    char ServiceName[MAX_PATH] = { 0 };
    char ServiceExt[50] = { 0 };
    PVOID ServiceBuffer = NULL;
    DWORD ServiceBufferSize = 0;
    BYTE ServiceType = 0;
    BYTE ServiceStart = 0;
    BYTE ErrorControl = 0;
    BOOL HasStarted = FALSE;

    BOOL GetDriverLoadPrivilege(const char* PrivilegeName) {
        HANDLE CurrTokenHandle = INVALID_HANDLE_VALUE;

        if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &CurrTokenHandle) || CurrTokenHandle == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        LUID PrivilegeLuid = { 0 };
        if (!LookupPrivilegeValueA(NULL, PrivilegeName, &PrivilegeLuid)) {
            return FALSE;
        }

        TOKEN_PRIVILEGES TokenState{};
        TokenState.PrivilegeCount = 1;
        TokenState.Privileges[0].Luid = PrivilegeLuid;
        TokenState.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if (!AdjustTokenPrivileges(CurrTokenHandle, FALSE, &TokenState, sizeof(TokenState), NULL, NULL)) {
            return FALSE;
        }

        CloseHandle(CurrTokenHandle);
        return TRUE;
    }

public:

    BOOL BufferOperation(PVOID Buffer, DWORD Size, BOOL IsRead) {
        if (Size > ServiceBufferSize) {
            return FALSE;
        }

        if (IsRead) {
            memcpy(Buffer, ServiceBuffer, Size);
        }
        else {
            memcpy(ServiceBuffer, Buffer, Size);
        }
        return TRUE;
    }


    BOOL GetRunning() {
        return HasStarted;
    }


    void GetServicePath(char* ServicePath) {
        RtlZeroMemory(ServicePath, MAX_PATH);
        memcpy(ServicePath, ServiceFile, strlen(ServiceFile) + 1);
    }


    void SetRunning(BOOL Runstat) {
        HasStarted = Runstat;
    }


    void SetServicePath(const char* ServicePath) {
        char TempPath[MAX_PATH] = { 0 };
        int NameIndex = 0;
        int ExtIndex = 0;
        int PathIndex = 0;
        int InitialPathSize = 0;
        const char* PathPrefix = "\\??\\";

        memcpy(ServiceFile, PathPrefix, strlen(PathPrefix));
        RtlZeroMemory(ServiceFile, MAX_PATH);
        if (ServicePath != NULL) {
            memcpy((PVOID)((ULONG64)ServiceFile + strlen(PathPrefix)), ServicePath, strlen(ServicePath) + 1);
        }
    }


    void FreeServiceBuffer() {
        if (ServiceBuffer != NULL) {
            free(ServiceBuffer);
        }
    }


    PVOID GetServiceBuffer() {
        return ServiceBuffer;
    }


    DWORD GetServiceBufSize() {
        return ServiceBufferSize;
    }


    BOOL DeleteServiceEntry() {
        SC_HANDLE ServiceManager = { 0 };
        SC_HANDLE ServiceHandle = { 0 };

        // Open the service -
        ServiceManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_ALL_ACCESS);
        if (!ServiceManager) {
            return FALSE;
        }
        ServiceHandle = OpenServiceA(ServiceManager, ServiceName, SERVICE_ALL_ACCESS);
        if (!ServiceHandle) {
            CloseServiceHandle(ServiceManager);
            return FALSE;
        }

        // Delete the service entry -
        if (!DeleteService(ServiceHandle)) {
            CloseServiceHandle(ServiceHandle);
            CloseServiceHandle(ServiceManager);
            return FALSE;
        }
        CloseServiceHandle(ServiceHandle);
        CloseServiceHandle(ServiceManager);
        return TRUE;
    }


    BOOL CreateServiceEntry(BOOL UseActual, char* NotActual) {
        SC_HANDLE ServiceManager = { 0 };
        SC_HANDLE ServiceHandle = { 0 };
        DWORD LastError = 0;

        // If the service already exists: delete it -
        ServiceManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
        if (!ServiceManager) {
            return FALSE;
        }
        ServiceHandle = OpenServiceA(ServiceManager, ServiceName, SERVICE_STOP);
        if (!ServiceHandle) {
            LastError = GetLastError();
            CloseServiceHandle(ServiceManager);
            if (LastError != ERROR_SERVICE_DOES_NOT_EXIST) {
                // Service already exists, error while getting handle for stopping it -
                return FALSE;
            }
        }
        else {
            // Service already exists: delete it -
            CloseServiceHandle(ServiceManager);
            CloseServiceHandle(ServiceHandle);
            if (!DeleteServiceEntry()) {
                return FALSE;
            }
        }


        // Open the Service Control Manager
        ServiceManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CREATE_SERVICE);
        if (!ServiceManager) {
            return FALSE;
        }

        char* ServiceFilePath = ServiceFile;
        if (!UseActual) {
            ServiceFilePath = NotActual;
        }


        // Create the service -
        ServiceHandle = CreateServiceA(ServiceManager, ServiceName, ServiceName, SERVICE_ALL_ACCESS, ServiceType, ServiceStart, ErrorControl, ServiceFilePath, NULL, NULL, NULL, NULL, NULL);
        CloseServiceHandle(ServiceManager);
        if (ServiceHandle) {
            CloseServiceHandle(ServiceHandle);
            return TRUE;
        }
        return FALSE;
    }


    BOOL UnloadService() {
        char TempPath[MAX_PATH] = { 0 };
        SC_HANDLE ServiceManager = { 0 };
        SC_HANDLE ServiceHandle = { 0 };
        SERVICE_STATUS LastStatus = { 0 };
        int NameIndex = 0;
        int ExtIndex = 0;
        int PathIndex = 0;
        int InitialPathSize = 0;

        // Get path to temp copy of file for deleting -
        if (GetTempPathA(MAX_PATH, TempPath) == 0) {
            return FALSE;
        }
        InitialPathSize = strlen(TempPath);

        for (PathIndex = InitialPathSize; PathIndex < strlen(ServiceName) + InitialPathSize; PathIndex++, NameIndex++) {
            TempPath[PathIndex] = ServiceName[NameIndex];
        }
        for (; PathIndex <= InitialPathSize + strlen(ServiceName) + strlen(ServiceExt); PathIndex++, ExtIndex++) {
            TempPath[PathIndex] = ServiceExt[ExtIndex];
        }

        // Stop the service -
        ServiceManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
        if (!ServiceManager) {
            return FALSE;
        }
        ServiceHandle = OpenServiceA(ServiceManager, ServiceName, SERVICE_STOP);
        if (!ServiceHandle) {
            CloseServiceHandle(ServiceManager);
            return FALSE;
        }
        BOOL UnloadSuccess = ControlService(ServiceHandle, SERVICE_CONTROL_STOP, &LastStatus);

        // Delete remains of the service and the used files (temp copy of driver, service entry) -
        BOOL DeleteServiceRes = DeleteServiceEntry();
        BOOL DeleteRes = DeleteFileA(TempPath);
        HasStarted = FALSE;
        return DeleteRes && DeleteServiceRes && UnloadSuccess;
    }


    BOOL LoadService() {
        char TempPath[MAX_PATH] = { 0 };
        SC_HANDLE ServiceManager = { 0 };
        SC_HANDLE ServiceHandle = { 0 };
        int NameIndex = 0;
        int ExtIndex = 0;
        int PathIndex = 0;
        int InitialPathSize = 0;
        NTSTATUS LoadStatus = 1;
        DWORD TempWrite = 0;
        HANDLE TempHandle;

        // Create copy of the services main file in temp directory for use of service -
        if (GetTempPathA(MAX_PATH, TempPath) == 0) {
            return FALSE;
        }
        InitialPathSize = strlen(TempPath);

        for (PathIndex = InitialPathSize; PathIndex < strlen(ServiceName) + InitialPathSize; PathIndex++, NameIndex++) {
            TempPath[PathIndex] = ServiceName[NameIndex];
        }
        for (; PathIndex <= InitialPathSize + strlen(ServiceName) + strlen(ServiceExt); PathIndex++, ExtIndex++) {
            TempPath[PathIndex] = ServiceExt[ExtIndex];
        }

        TempHandle = CreateFileA(TempPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
        if (TempHandle == INVALID_HANDLE_VALUE) {
            return FALSE;
        }

        if (!WriteFile(TempHandle, ServiceBuffer, ServiceBufferSize, &TempWrite, NULL) || TempWrite != ServiceBufferSize) {
            CloseHandle(TempHandle);
            return FALSE;
        }
        CloseHandle(TempHandle);


        if (ServiceType == SERVICE_KERNEL_DRIVER) {
            if (!GetDriverLoadPrivilege("SeLoadDriverPrivilege")) {
                return FALSE;
            }
        }


        // Start the service -
        if (!CreateServiceEntry(FALSE, TempPath)) {
            return FALSE;
        }

        ServiceManager = OpenSCManagerW(NULL, SERVICES_ACTIVE_DATABASE, SC_MANAGER_CONNECT);
        if (!ServiceManager) {
            return FALSE;
        }
        ServiceHandle = OpenServiceA(ServiceManager, ServiceName, SERVICE_START);
        if (!ServiceHandle) {
            return FALSE;
        }
        if (!StartServiceA(ServiceHandle, 0, NULL)) {
            return FALSE;
        }
        CloseServiceHandle(ServiceManager);
        CloseServiceHandle(ServiceHandle);
        HasStarted = TRUE;
        return TRUE;
    }


    BOOL InitiateService(const char* ServicePath, BYTE Type, BYTE ErrorCont, BYTE Start, const char* Name, DWORD BufferSize, const char* Extension) {
        RtlZeroMemory(ServiceName, MAX_PATH);
        memcpy(ServiceName, Name, strlen(Name) + 1);  // Name of the service that will identify it
        RtlZeroMemory(ServiceExt, 50);
        memcpy(ServiceExt, Extension, strlen(Extension) + 1);
        SetServicePath(ServicePath);  // Service path should be a full path to the file used by the service
        ServiceType = Type;
        ErrorControl = ErrorCont;
        ServiceStart = Start;
        HasStarted = FALSE;
        ServiceBufferSize = BufferSize;
        ServiceBuffer = malloc(ServiceBufferSize);
        if (ServiceBuffer == NULL) {
            return FALSE;
        }
        return TRUE;
    }
};