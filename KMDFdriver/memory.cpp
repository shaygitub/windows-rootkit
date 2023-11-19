#include "memory.h"
#pragma warning(disable:4996)

/*
=====================================================================
=====================================================================
INTERNAL MEMORY FUNCTIONS THAT DO NOT CORRELATE TO REQUESTS, GENERAL:
=====================================================================
=====================================================================
*/




PVOID SystemModuleBaseMEM(const char* module_name) {
	//DbgPrintEx(0, 0, "KMDFdriver GET MODULE BASE\n");

	ULONG bytes = 0;
	ULONG queried_bytes = 0;
	NTSTATUS status = ZwQuerySystemInformation(SystemModuleInformation, NULL, bytes, &queried_bytes);  // returns the needed size for information to queried_bytes

	if (queried_bytes == 0) {
		return NULL;  // Query did not work correctly (size of data returned is not valid)
	}
	bytes = queried_bytes;
	
	
	// Actual query for system information -
	PVOID ModulesInfo = ExAllocatePoolWithTag(NonPagedPool, bytes, 0x526B506C);  // tag name is "RkPl"
	if (ModulesInfo == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver GET MODULE BASE CANNOT ALLOCATE BUFFER FOR ACTUAL SYSQUERY :(\n");
		return NULL;
	}
	status = ZwQuerySystemInformation(SystemModuleInformation, ModulesInfo, bytes, &queried_bytes);

	if (!NT_SUCCESS(status)) {		
		if (status == STATUS_INFO_LENGTH_MISMATCH) {
			bytes = queried_bytes;

			// reallocate the buffer so the sizes will be compatible and requery the information -
			if (ModulesInfo != NULL) {
				ExFreePool(ModulesInfo);
			}

			ModulesInfo = ExAllocatePoolWithTag(NonPagedPool, bytes, 0x526B506C);  // tag name is "RkPl"
			if (ModulesInfo == NULL) {
				return NULL;
			}

			status = ZwQuerySystemInformation(SystemModuleInformation, ModulesInfo, bytes, &queried_bytes);
			if (!NT_SUCCESS(status)) {
				return NULL;
			}
		}
		else {
			return NULL;  // Pool allocation for system modules did not succeed
		}
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver INITIAL MODULE BASE QUERY SYSTEM MODULE INFORMATION SUCCEEDED :)\n");
	}

	PRTL_PROCESS_MODULE_INFORMATION module = ((PRTL_PROCESS_MODULES)ModulesInfo)->Modules;  // Module is a pointer to the actual system modules 
	PVOID module_base = 0;
	ULONG module_size = 0;  // Will save information about the required module

	for (ULONG i = 0; i < ((PRTL_PROCESS_MODULES)ModulesInfo)->NumberOfModules; i++) {
		if (strcmp((char*)module[i].FullPathName, module_name) == 0) {

			// Found the required module in the system modules list
			module_base = module[i].ImageBase;
			module_size = module[i].ImageSize;
			break;
		}
	}

	if (ModulesInfo != NULL) {
		ExFreePool(ModulesInfo);
	}

	if (module_size <= 0) {
		return NULL;  // Size specified in system modules list is incorrect
	}

	return module_base;
}




PVOID SystemModuleExportMEM(const char* module_name, LPCSTR routine_name) {
	//DbgPrintEx(0, 0, "KMDFdriver GET FUNCTION FROM MODULE\n");

	PVOID ModuleP = SystemModuleBaseMEM(module_name);
	if (!ModuleP) {
		return NULL;  // Couldn't get module base - cannot find a function inside a non existing module
	}
	return RtlFindExportedRoutineByName(ModuleP, routine_name);  // Routine_name = function name from system module (driver)
}




bool WriteMemoryMEM(void* address, void* buffer, size_t size) {
	// DbgPrintEx(0, 0, "KMDFdriver WRITING TO REGULAR MEMORY\n");

	if (!RtlCopyMemory(address, buffer, size)) {
		DbgPrintEx(0, 0, "KMDFdriver FAILED WRITING TO REGULAR MEMORY :(\n");
		return FALSE;
	}
	return TRUE;
}




bool WriteToReadOnlyMemoryMEM(void* address, void* buffer, size_t size) {
	// DbgPrintEx(0, 0, "KMDFdriver WRITING TO READ ONLY MEMORY\n");
	PMDL Mdl = IoAllocateMdl(address, (ULONG)size, FALSE, FALSE, NULL);  // Create descriptor for a range of memory pages, required for handling a page range

	if (!Mdl) {
		DbgPrintEx(0, 0, "KMDFdriver COULD NOT CREATE MEMORY DESCRIPTOR :(\n");
		return FALSE;  // Descriptor couldn't be created
	}

	// Lock the pages in physical memory (similar to NonPaged pool concept) -
	MmProbeAndLockPages(Mdl, KernelMode, IoReadAccess);
	
	// Map the memory pages into other virtual memory range -
	PVOID Mapping = MmMapLockedPagesSpecifyCache(Mdl, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	
	// Set the protection settings of the page range to be both writeable and readable -
	MmProtectMdlSystemAddress(Mdl, PAGE_READWRITE);

	// Write into the mapped pages -
	WriteMemoryMEM(Mapping, buffer, size);

	// Unmap the page range -
	MmUnmapLockedPages(Mapping, Mdl);

	// Unlock the page range -
	MmUnlockPages(Mdl);

	// Free the pages descriptor used for page range -
	IoFreeMdl(Mdl);

	return TRUE;
}




NTSTATUS UserToKernelMEM(PEPROCESS SrcProcess, PVOID UserAddress, PVOID KernelAddress, SIZE_T Size, BOOL IsAttached) {
	KAPC_STATE SrcState = { 0 };

	// Check for invalid parameters -
	if (!SrcProcess || !UserAddress || !KernelAddress || !Size) {
		DbgPrintEx(0, 0, "KMDFdriver GetUserToKernel FAILED - INVALID ARGS SIZE (%zu)/USER BUFFER (%p)/KERNEL BUFFER (%p)/HANDLE (%p)\n", Size, UserAddress, KernelAddress, SrcProcess);
		return STATUS_INVALID_PARAMETER;
	}

	// Attach to the usermode process if needed -
	if (!IsAttached) {
		KeStackAttachProcess(SrcProcess, &SrcState);  // attach to source usermode process
	}

	// Perform the copying -
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(KernelAddress, UserAddress, Size);

		// Detach from the usermode process if needed -
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);  // detach from source usermode process
		}
		DbgPrintEx(0, 0, "KMDFdriver GetUserToKernel SUCCEEDED - RtlCopyMemory SUCCEEDED\n");
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver GetUserToKernel FAILED - RtlCopyMemory ACCESS VIOLATION/USERMODE ADDRESS OUT OF PROCESS ADDRESS SPACE (%p)\n", UserAddress);

		// Detach from the usermode process if needed -
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);  // detach from source usermode process
		}
		return STATUS_ACCESS_VIOLATION;
	}
}




NTSTATUS KernelToUserMEM(PEPROCESS DstProcess, PVOID KernelAddress, PVOID UserAddress, SIZE_T Size, BOOL IsAttached) {
	KAPC_STATE DstState = { 0 };

	// Check for invalid parameters -
	if (!DstProcess || !UserAddress || !KernelAddress || !Size) {
		DbgPrintEx(0, 0, "KMDFdriver GetKernelToUser FAILED - INVALID ARGS SIZE (%zu)/USER BUFFER (%p)/KERNEL BUFFER (%p)/HANDLE (%p)\n", Size, UserAddress, KernelAddress, DstProcess);
		return STATUS_INVALID_PARAMETER;
	}

	// Attach to the usermode process if needed -
	if (!IsAttached) {
		KeStackAttachProcess(DstProcess, &DstState);  // attach to destination usermode process
	}

	// Perform the copying -
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(UserAddress, KernelAddress, Size);

		// Detach from the usermode process if needed -
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);  // detach from destination usermode process
		}
		DbgPrintEx(0, 0, "KMDFdriver GetKernelToUser SUCCEEDED - RtlCopyMemory SUCCEEDED\n");
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver GetKernelToUser FAILED - RtlCopyMemory ACCESS VIOLATION/USERMODE ADDRESS OUT OF PROCESS ADDRESS SPACE (%p)\n", UserAddress);

		// Detach from the usermode process if needed -
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);  // detach from destination usermode process
		}
		return STATUS_ACCESS_VIOLATION;
	}
}




PVOID CommitMemoryRegionsADD(HANDLE ProcessHandle, PVOID Address, SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit) {
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION info = { 0 };
	PVOID InitialAddress = Address;
	SIZE_T RequestedSize = Size;
	if (ExistingAllocAddr != NULL) {
		Address = ExistingAllocAddr;
	}


	// Allocate the actual needed pages and save them for later allocating -
	if (Address != ExistingAllocAddr) {
		__try {
			ProbeForRead(Address, Size, sizeof(UCHAR));
			status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);
		}
		__except (STATUS_ACCESS_VIOLATION) {
			DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD REQUEST FAILED - ACCESS VIOLATION WITH WRITING ADDRESS IN ADDRESS RANGE OF DESTINATION (ADDRESS: %p) :(\n", Address);
			return NULL;
		}

		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD INITIAL REQUEST FAILED VIRTMEM ALLOC INITIAL (GENERAL PAGE), TRYING TO GET ANY MEMORY POSSIBLE..\n");
			Address = NULL;  // required to tell the system to choose where to allocate the memory
			status = ZwAllocateVirtualMemory(ProcessHandle, &Address, 0, &Size, MEM_RESERVE, PAGE_NOACCESS);  // Size and Address are alligned here after the first call
			if (!NT_SUCCESS(status)) {
				DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD REQUEST FAILED TO GET ANY POSSIBLE MEMORY AREA (GENERAL PAGE) :(\n");
				return NULL;
			}
		}
	}
	DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD INITIAL ADDRESS: %p, ALLOCATION ADDRESS (NEW ADDRESS): %p\n", InitialAddress, Address);
	DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD REQUESTED SIZE: %zu, ALLOCATION SIZE (NEW SIZE): %zu\n", RequestedSize, Size);


	// Allocate the range of pages in processes virtual memory with the required allocation type and protection settings -
	status = STATUS_UNSUCCESSFUL;
	status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_COMMIT, AllocProt);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD REQUEST FAILED VIRTMEM ALLOC FINAL (CHANGE TO PAGE_READWRITE) :(\n");
		if (Address != ExistingAllocAddr) {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_RELEASE);  // Release the unused memory
		}
		else {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_DECOMMIT);  // de-commit the unused memory
		}
		return NULL;
	}


	// Query to verify the change of memory state (NOT MANDATORY: DOES NOT CHANGE RETURN VALUE + DOES NOT FREE ALLOCATION IF FAILED) -
	status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &info, sizeof(info), NULL);
	if (!NT_SUCCESS(status)) {
		DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD REQUEST FAILED VIRTMEM QUERY :(\n");
		return Address;
	}

	if (!(info.State & MEM_COMMIT)) {
		DbgPrintEx(0, 0, "KMDFdriver CommitMemoryRegionsADD REQUEST DOES NOT INCLUDE STATE SETTINGS OF MEM_COMMIT :(\n");
	}
	return Address;
}




BOOL ChangeProtectionSettingsADD(HANDLE ProcessHandle, PVOID Address, ULONG Size, ULONG ProtSettings, ULONG OldProtect) {
	MEMORY_BASIC_INFORMATION info = { 0 };
	NTSTATUS status = STATUS_UNSUCCESSFUL;


	// Change the protection settings of the whole memory range -
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		status = ZwProtectVirtualMemory(ProcessHandle, &Address, &Size, ProtSettings, &OldProtect);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "KMDFdriver ChangeProtectionSettingsADD REQUEST FAILED VIRTMEM PROTECTION :(\n");
			return FALSE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver ChangeProtectionSettingsADD PROTECTION FAILED - VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/IS NOT READABLE\n");
		return FALSE;
	}

	// Query to verify that changes were done (NOT MANDATORY: DOES NOT CHANGE RETURN VALUE) -
	status = STATUS_UNSUCCESSFUL;
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &info, sizeof(info), NULL);
		if (!NT_SUCCESS(status)) {
			DbgPrintEx(0, 0, "KMDFdriver ChangeProtectionSettingsADD REQUEST FAILED VIRTMEM QUERY :(\n");
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver ChangeProtectionSettingsADD VERIFICATION FAILED - VIRTMEM ADDRESS IS NOT IN THE ADDRESS RANGE/ITS NOT READABLE\n");
		return TRUE;
	}

	if (NT_SUCCESS(status) && (info.Protect & ProtSettings) && !(info.Protect & PAGE_GUARD || info.Protect & PAGE_NOACCESS)) {
		DbgPrintEx(0, 0, "KMDFdriver ChangeProtectionSettingsADD REQUEST FAILED TO ADD WRITING PERMS (PAGE-NOACCESS/PAGE-GUARD / !PROTSETTINGS) :(\n");
		return FALSE;
	}
	return TRUE;
}