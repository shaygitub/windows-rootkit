#include "piping.h"


BOOL OpenPipe(HANDLE* PipeHandle, const char* PipeName, LogFile* MediumLog) {
    *PipeHandle = CreateNamedPipeA(
        PipeName,             // pipe name 
        PIPE_ACCESS_DUPLEX,       // read/write access 
        PIPE_TYPE_MESSAGE |       // message type pipe 
        PIPE_READMODE_MESSAGE |   // message-read mode 
        PIPE_WAIT |                // blocking mode 
        PIPE_REJECT_REMOTE_CLIENTS,  // Make sure that remote clients cannot connect to this pipe
        1,                      // One instance in every use, one client and one server
        1024,                  // output buffer size 
        1024,                  // input buffer size 
        0,                        // client time-out 
        NULL);                    // default security attribute 

    if (*PipeHandle == INVALID_HANDLE_VALUE){
        MediumLog->WriteError("MainMedium piping - OpenPipe() returned INVALID_HANDLE_VALUE", GetLastError());
        return FALSE;
    }
    MediumLog->WriteLog((PVOID)"MainMedium piping - OpenPipe() succeeded\n", 42);
    return TRUE;
}


DWORD WritePipe(HANDLE* PipeHandle, PVOID InputBuffer, SIZE_T BufferSize, LogFile* MediumLog) {
    DWORD BytesWritten = 0;
    DWORD LastError = 0;
    if (!WriteFile(*PipeHandle, InputBuffer, (DWORD)BufferSize, &BytesWritten, NULL)) {
        LastError = GetLastError();
        MediumLog->WriteError("MainMedium piping - WritePipe() failed", LastError);
        return LastError;
    }
    if (BytesWritten != BufferSize) {
        MediumLog->WriteError("MainMedium piping - WritePipe() unfinished write", STATUS_UNSUCCESSFUL);
        return STATUS_UNSUCCESSFUL;
    }
    MediumLog->WriteLog((PVOID)"MainMedium piping - WritePipe() succeeded", 42);
    return 0;
}


DWORD ReadPipe(HANDLE* PipeHandle, PVOID OutputBuffer, SIZE_T BufferSize, LogFile* MediumLog){
    DWORD BytesRead = 0;
    DWORD LastError = 0;
    if (!ReadFile(*PipeHandle, OutputBuffer, (DWORD)BufferSize, &BytesRead, NULL)) {
        LastError = GetLastError();
        MediumLog->WriteError("MainMedium piping - ReadPipe() failed", LastError);
        return LastError;
    }
    if (BytesRead != BufferSize) {
        MediumLog->WriteError("MainMedium piping - ReadPipe() unfinished read", STATUS_UNSUCCESSFUL);
        return STATUS_UNSUCCESSFUL;
    }
    MediumLog->WriteLog((PVOID)"MainMedium piping - ReadPipe() succeeded", 41);
    return 0;
}