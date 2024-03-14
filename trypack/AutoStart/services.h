#pragma once
#include <Windows.h>
#include <iostream>
#include <Winternl.h>
#include <string>
#include <fstream>
#include "utils.h"
#pragma warning( disable : 4267)
#pragma warning( disable : 4244)
#pragma comment(lib, "ntdll.lib")


// Class used to represent the actual service and its attributes -
class AutoService {
public:
    SERVICE_STATUS ServiceStatus = { 0 };  // Used to report the status of the service to SCM
    SERVICE_STATUS_HANDLE StatusHandle = { 0 };  // Used to refrence service after registration of service
    HANDLE StopEvent = INVALID_HANDLE_VALUE;  // Holds the handle for the event that occurs after stopping the service
    HANDLE MainThread = INVALID_HANDLE_VALUE;  // Holds the main thread that service is based upon
    WCHAR ServiceName[MAX_PATH] = { 0 };
    const char* ServiceFile = { 0 };

    void InitiateService(WCHAR* Name) {
        RtlZeroMemory(ServiceName, MAX_PATH);
        RtlCopyMemory(ServiceName, Name, (wcslen(Name) + 1) * sizeof(WCHAR));
    }
};
AutoService AutomaticService;