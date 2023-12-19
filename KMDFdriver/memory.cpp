#include "memory.h"
#pragma warning(disable:4996)




PVOID SystemModuleBaseMEM(const char* ModuleName) {
	DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module\n");
	ULONG Size = 0;
	ULONG NeededSize = 0;
	ULONG ModuleSize = 0;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PRTL_PROCESS_MODULE_INFORMATION CurrentModule = NULL;  // CurrentModule is a pointer to the current system module when querying
	PVOID ModuleBase = NULL;
	PVOID ModulesInfo = NULL;


	// Check for invalid parameters:
	if (ModuleName == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (invalid parameter: NULL)\n");
		return NULL;
	}


	// Get the needed size for querying the system modules list:
	Status = ZwQuerySystemInformation(SystemModuleInformation, NULL, Size, &NeededSize);
	if (NeededSize == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (needed size for pool returned as 0)\n");
		return NULL;  // Query did not work correctly (size of data returned is not valid)
	}
	Size = NeededSize;
	
	
	// Actual query for system information:
	ModulesInfo = ExAllocatePoolWithTag(NonPagedPool, Size, 'MmMp');
	if (ModulesInfo == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (allocation of memory pool failed)\n");
		return NULL;
	}
	Status = ZwQuerySystemInformation(SystemModuleInformation, ModulesInfo, Size, &NeededSize);


	// Make sure that query was executed successfully, if size mismatch - query again:
	if (!NT_SUCCESS(Status)) {
		if (Status == STATUS_INFO_LENGTH_MISMATCH) {
			Size = NeededSize;
			if (ModulesInfo != NULL) {
				ExFreePool(ModulesInfo);
			}
			ModulesInfo = ExAllocatePoolWithTag(NonPagedPool, Size, 'MmMp');
			if (ModulesInfo == NULL) {
				DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (allocation of memory pool after mismatch failed)\n");
				return NULL;
			}
			Status = ZwQuerySystemInformation(SystemModuleInformation, ModulesInfo, Size, &NeededSize);
			if (!NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (query after mismatch failed: 0x%x)\n", Status);
				ExFreePool(ModulesInfo);
				return NULL;
			}
		}
		else {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (query failed: 0x%x)\n", Status);
			ExFreePool(ModulesInfo);
			return NULL;
		}
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module query succeeded first try\n");
	}


	// Search in system modules list for the driver to find (module to find):
	CurrentModule = ((PRTL_PROCESS_MODULES)ModulesInfo)->Modules;
	for (ULONG i = 0; i < ((PRTL_PROCESS_MODULES)ModulesInfo)->NumberOfModules; i++) {
		if (strcmp((char*)CurrentModule[i].FullPathName, ModuleName) == 0) {
			ModuleBase = CurrentModule[i].ImageBase;
			ModuleSize = CurrentModule[i].ImageSize;
			break;
		}
	}
	if (ModulesInfo != NULL) {
		ExFreePool(ModulesInfo);
	}
	if (ModuleSize <= 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module failed (returned size of module is 0)\n");
		return NULL;
	}
	DbgPrintEx(0, 0, "KMDFdriver Memory - Get base of system module succeeded (possibly), base = %p\n", ModuleBase);
	return ModuleBase;
}




PVOID SystemModuleExportMEM(const char* ModuleName, const char* RoutineName) {
	DbgPrintEx(0, 0, "KMDFdriver Memory - Get function from system module\n");
	PVOID ModuleBase = NULL;
	PVOID RoutineAddress = NULL;


	// Check for invalid parameters:
	if (ModuleName == NULL || RoutineName == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get function from system module failed (one or more invalid paramters: %p, %p)\n", ModuleName, RoutineName);
		return NULL;
	}


	// Find routine address:
	ModuleBase = SystemModuleBaseMEM(ModuleName);
	if (ModuleBase == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get function from system module failed (module base of relevant module returned as NULL)\n");
		return NULL;
	}
	RoutineAddress = RtlFindExportedRoutineByName(ModuleBase, RoutineName);
	if (RoutineAddress == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get function from system module failed (address = NULL)\n");
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Get function from system module succeeded, address = %p\n", RoutineAddress);
	}
	return RoutineAddress;
}




BOOL WriteMemoryMEM(PVOID WriteAddress, PVOID SourceBuffer, SIZE_T WriteSize) {
	//DbgPrintEx(0, 0, "KMDFdriver Memory - Write into system memory\n");
	
	
	// Check for invalid parameters:
	if (WriteAddress == NULL || SourceBuffer == NULL || WriteSize == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Write into system memory failed (one or more invalid parameters: %p, %p, %zu)\n", WriteAddress, SourceBuffer, WriteSize);
		return FALSE;
	}


	// Write to memory:
	if (!RtlCopyMemory(WriteAddress, SourceBuffer, WriteSize)) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Write into system memory failed\n");
		return FALSE;
	}
	//DbgPrintEx(0, 0, "KMDFdriver Memory - Write into system memory succeeded\n");
	return TRUE;
}




BOOL WriteToReadOnlyMemoryMEM(PVOID Address, PVOID Buffer, SIZE_T Size, BOOL IsWrite) {
	//DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory (mostly drivers / kernel functions)\n");
	PMDL MemoryDescriptor = NULL;
	PVOID MappedMemory = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid parameters:
	if (Address == NULL || Buffer == NULL || Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory failed (one or more invalid parameters: %p, %p, %zu)\n", Address, Buffer, Size);
		return FALSE;
	}


	// Create a memory descriptor for the memory range for operation on memory:
	if (IsWrite) {
		MemoryDescriptor = IoAllocateMdl(Address, (ULONG)Size, FALSE, FALSE, NULL);
	}
	else {
		MemoryDescriptor = IoAllocateMdl(Buffer, (ULONG)Size, FALSE, FALSE, NULL);
	}
	if (MemoryDescriptor == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory failed (cannot allocate memory descriptor)\n");
		return FALSE;
	}


	// Lock the pages in physical memory (similar to NonPaged pool concept):
	MmProbeAndLockPages(MemoryDescriptor, KernelMode, IoReadAccess);
	

	// Map the memory pages into system virtual memory:
	MappedMemory = MmMapLockedPagesSpecifyCache(MemoryDescriptor, KernelMode, MmNonCached, NULL, FALSE, NormalPagePriority);
	if (MappedMemory == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory failed (mapped system virtual memory is NULL)\n");
		MmUnlockPages(MemoryDescriptor);
		IoFreeMdl(MemoryDescriptor);
		return FALSE;
	}


	// Set the protection settings of the memory range to be both writeable and readable:
	Status = MmProtectMdlSystemAddress(MemoryDescriptor, PAGE_READWRITE);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory failed (failed to change protection settings of memory range: 0x%x)\n", Status);
		MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
		MmUnlockPages(MemoryDescriptor);
		IoFreeMdl(MemoryDescriptor);
		return FALSE;
	}


	// Write/Read into the mapped pages:
	if (IsWrite) {
		if (!WriteMemoryMEM(MappedMemory, Buffer, Size)) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory failed (write to mapped memory failed)\n");
			MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
			MmUnlockPages(MemoryDescriptor);
			IoFreeMdl(MemoryDescriptor);
			return FALSE;
		}
	}
	else {
		if (!WriteMemoryMEM(Address, MappedMemory, Size)) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory failed (read from mapped memory failed)\n");
			MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
			MmUnlockPages(MemoryDescriptor);
			IoFreeMdl(MemoryDescriptor);
			return FALSE;
		}
	}

	//DbgPrintEx(0, 0, "KMDFdriver Memory - Operate on system read-only memory succeeded\n");
	MmUnmapLockedPages(MappedMemory, MemoryDescriptor);
	MmUnlockPages(MemoryDescriptor);
	IoFreeMdl(MemoryDescriptor);
	return TRUE;
}




NTSTATUS UserToKernelMEM(PEPROCESS SrcProcess, PVOID UserAddress, PVOID KernelAddress, SIZE_T Size, BOOL IsAttached) {
	DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from UM to KM\n");
	KAPC_STATE SrcState = { 0 };


	// Check for invalid parameters:
	if (SrcProcess == NULL || UserAddress == NULL || KernelAddress == NULL || Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from UM to KM failed (one or more invalid parameters: %p, %p, %p, %zu)\n", (PVOID)SrcProcess, UserAddress, KernelAddress, Size);
		return STATUS_INVALID_PARAMETER;
	}


	// Attach to the usermode process if needed:
	if (!IsAttached) {
		KeStackAttachProcess(SrcProcess, &SrcState);
	}


	// Perform the transfer:
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(KernelAddress, UserAddress, Size);
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);
		}
		DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from UM to KM succeeded\n");
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from UM to KM failed (access violation kernel exception)\n");
		if (!IsAttached) {
			KeUnstackDetachProcess(&SrcState);
		}
		return STATUS_ACCESS_VIOLATION;
	}
}




NTSTATUS KernelToUserMEM(PEPROCESS DstProcess, PVOID KernelAddress, PVOID UserAddress, SIZE_T Size, BOOL IsAttached) {
	DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from KM to UM\n");
	KAPC_STATE DstState = { 0 };



	// Check for invalid parameters:
	if (DstProcess == NULL || KernelAddress == NULL || UserAddress == NULL || Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from KM to UM failed (one or more invalid parameters: %p, %p, %p, %zu)\n", (PVOID)DstProcess, KernelAddress, UserAddress, Size);
		return STATUS_INVALID_PARAMETER;
	}


	// Attach to the usermode process if needed:
	if (!IsAttached) {
		KeStackAttachProcess(DstProcess, &DstState);
	}


	// Perform the transfer:
	__try {
		ProbeForRead(UserAddress, Size, sizeof(UCHAR));
		RtlCopyMemory(UserAddress, KernelAddress, Size);
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);
		}
		DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from KM to UM succeeded\n");
		return STATUS_SUCCESS;
	}

	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Transfer data from KM to UM failed (access violation kernel exception)\n");
		if (!IsAttached) {
			KeUnstackDetachProcess(&DstState);
		}
		return STATUS_ACCESS_VIOLATION;
	}
}




PVOID CommitMemoryRegionsADD(HANDLE ProcessHandle, PVOID Address, SIZE_T Size, ULONG AllocProt, PVOID ExistingAllocAddr, ULONG_PTR ZeroBit) {
	DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process\n");
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };
	PVOID InitialAddress = Address;
	SIZE_T RequestedSize = Size;


	// Check for invalid parameters:
	if (ProcessHandle == NULL || Address == NULL || Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process failed (one or more invalid parameters: %p, %p, %zu)\n", ProcessHandle, Address, Size);
		return NULL;
	}


	// Allocate the actual needed pages and save them for committing later:
	if (ExistingAllocAddr != NULL) {
		Address = ExistingAllocAddr;
	}
	if (Address != ExistingAllocAddr) {
		__try {
			ProbeForRead(Address, Size, sizeof(UCHAR));
			Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);
		}
		__except (STATUS_ACCESS_VIOLATION) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process failed (access violation system exception)\n");
			return NULL;
		}

		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process with specific ZeroBit failed (ZwAllocateVirtualMemory returned 0x%x, ZeroBit = %llu)\n", Status, (ULONG64)ZeroBit);
			Address = NULL;  // Required to tell the system to choose where to allocate the memory
			ZeroBit = 0;
			Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_RESERVE, PAGE_NOACCESS);  // Size and Address are alligned here after the first call
			if (!NT_SUCCESS(Status)) {
				DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process after trying with specific ZeroBit failed (ZwAllocateVirtualMemory returned 0x%x, no possible free memory)\n", Status);
				return NULL;
			}
		}
	}
	DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process: Initial addrsize = (%p, %zu), New addrsize = (%p, %zu)\n", InitialAddress, RequestedSize, Address, Size);


	// Allocate the range of pages in processes virtual memory with the required allocation type and protection settings:
	Status = ZwAllocateVirtualMemory(ProcessHandle, &Address, ZeroBit, &Size, MEM_COMMIT, AllocProt);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process failed (committing memory with protection settings of %lu failed: 0x%x)\n", AllocProt, Status);
		if (Address != ExistingAllocAddr) {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_RELEASE);  // Release the unused memory
		}
		else {
			ZwFreeVirtualMemory(ProcessHandle, &Address, &Size, MEM_DECOMMIT);  // De-commit the unused memory
		}
		return NULL;
	}
	DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process succeeded (address = %p, size = %zu), checking if changed\n", Address, Size);


	// Query to verify the change of memory state:
	Status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), NULL);
	if (!NT_SUCCESS(Status)) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process failed to query memory for checking if committed (ZwQueryVirtualMemory retuned 0x%x)\n", Status);
		return Address;
	}

	if (!(MemoryInfo.State & MEM_COMMIT)) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process failed (ZwQueryVirtualMemory returned that area is not committed, but it is %lu)\n", MemoryInfo.State);
		return NULL;
	}
	DbgPrintEx(0, 0, "KMDFdriver Memory - Commit memory regions in process succeeded, verified that memory is committed\n");
	return Address;
}




BOOL ChangeProtectionSettingsADD(HANDLE ProcessHandle, PVOID Address, ULONG Size, ULONG ProtSettings, ULONG OldProtect) {
	DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process\n");
	MEMORY_BASIC_INFORMATION MemoryInfo = { 0 };
	NTSTATUS Status = STATUS_UNSUCCESSFUL;


	// Check for invalid parameters:
	if (ProcessHandle == NULL || Address == NULL || Size == 0) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process failed (one or more invalid parameters: %p, %p, %lu)\n", ProcessHandle, Address, Size);
		return FALSE;
	}


	// Change the protection settings of the whole memory range:
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		Status = ZwProtectVirtualMemory(ProcessHandle, &Address, &Size, ProtSettings, &OldProtect);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process failed (ZwProtectVirtualMemory returned 0x%x)\n", Status);
			return FALSE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process failed (access violation system exception)\n");
		return FALSE;
	}
	DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process succeeded, checking if changed\n");


	// Query to verify that changes were done:
	__try {
		ProbeForRead(Address, Size, sizeof(UCHAR));
		Status = ZwQueryVirtualMemory(ProcessHandle, Address, MemoryBasicInformation, &MemoryInfo, sizeof(MemoryInfo), NULL);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process failed to query memory to check (ZwQueryVirtualMemory returned 0x%x)\n", Status);
			return TRUE;
		}
	}
	__except (STATUS_ACCESS_VIOLATION) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process failed to query memory to check (ZwQueryVirtualMemory caused an access violation system exception)\n");
		return TRUE;
	}

	if ((MemoryInfo.Protect & ProtSettings) && !(MemoryInfo.Protect & PAGE_GUARD || MemoryInfo.Protect & PAGE_NOACCESS)) {
		DbgPrintEx(0, 0, "KMDFdriver Memory - Change protection of memory regions in process failed (after query memory is protected by PAGE_NOACCESS/PAGE_GUARD and/or it does not include the required protection settings of %lu)\n", ProtSettings);
		return FALSE;
	}
	return TRUE;
}