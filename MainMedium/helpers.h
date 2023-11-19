#pragma once
#include "medium.h"

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