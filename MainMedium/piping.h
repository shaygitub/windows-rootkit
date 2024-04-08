#pragma once
#include "helpers.h"


BOOL OpenPipe(HANDLE* PipeHandle, const char* PipeName, LogFile* MediumLog);
DWORD WritePipe(HANDLE* PipeHandle, PVOID InputBuffer, SIZE_T BufferSize, LogFile* MediumLog);
DWORD ReadPipe(HANDLE* PipeHandle, PVOID OutputBuffer, SIZE_T BufferSize, LogFile* MediumLog);