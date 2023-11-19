#pragma once
#include "definitions.h"

PVOID SystemModuleBaseMEM(const char* module_name);  // Get a pointer to a system module (driver)
PVOID SystemModuleExportMEM(const char* module_name, LPCSTR routine_name);  // Get a pointer to a function within a system module (driver)
bool WriteMemoryMEM(void* address, void* buffer, size_t size);  // Write to memory with writing access (uses RtlCopyMemory + basic true/false)
bool WriteToReadOnlyMemoryMEM(void* address, void* buffer, size_t size);  // uses WriteToMemory to write into read-only memory (mostly for hooking system modules/system space components)
NTSTATUS UserToKernelMEM(PEPROCESS SrcProcess, PVOID UserAddress, PVOID KernelAddress, SIZE_T Size, BOOL IsAttached);  // general use to copy data from UM to KM
NTSTATUS KernelToUserMEM(PEPROCESS DstProcess, PVOID KernelAddress, PVOID UserAddress, SIZE_T Size, BOOL IsAttached);  // general use to copy data from KM to UM
PVOID CommitMemoryRegionsADD(HANDLE ProcessHandle, PVOID Address, SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit);  // try to commit reserved memory / reserve + commit free memory for writing into
BOOL ChangeProtectionSettingsADD(HANDLE ProcessHandle, PVOID Address, ULONG Size, ULONG ProtSettings, ULONG OldProtect);  // try to change the protection settings of virtual memory regions (used mostly to get write access to virtual memory regions)
