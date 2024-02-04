#pragma once
#include <ntstatus.h>
#include <Windows.h>
#include <iostream>

namespace VulnurableDriver {
	namespace IoctlFunctions {
		BOOL MemoryCopy(HANDLE* DeviceHandle, PVOID DestinationAddress, PVOID SourceAddress, ULONG64 CopySize);  // Case number 0x33
		BOOL MemoryFill(HANDLE* DeviceHandle, PVOID FillAddress, ULONG FillValue, ULONG64 FillSize);  // Case number 0x30
		BOOL VirtualToPhysical(HANDLE* DeviceHandle, PVOID VirtualAddress, PVOID* PhysicalAddress);  // Case number 0x25
		PVOID MapIoSpace(HANDLE* DeviceHandle, PVOID PhysicalAddress, ULONG MappingSize);  // Case number 0x19
		BOOL UnmapIoSpace(HANDLE* DeviceHandle, PVOID MappingAddress, ULONG MappingSize);  // Case number 0x1A
    }
	namespace HelperFunctions {
		BOOL IsAlreadyRunning(const char* SymbolicLink);  // Checked by the device handle, not the file/full path handle
		PVOID FindSectionFromKernelModule(HANDLE* DeviceHandle, const char* SectionName, PVOID ModulePointer, ULONG* SectionSize);
		PVOID FindPatternInKernelModule(HANDLE* DeviceHandle, PVOID SearchAddress, ULONG64 SearchLength, BYTE CompareAgainst[], const char* SearchMask);
		PVOID FindPatternInSectionOfKernelModule(HANDLE* DeviceHandle, const char* SectionName, PVOID ModulePointer, BYTE CompareAgainst[], const char* SearchMask);
		PVOID VulnurableDriver::HelperFunctions::RelativeAddressToActual(HANDLE* DeviceHandle, PVOID Instruction, ULONG Offset, ULONG InstructionSize);
	}
	namespace PersistenceFunctions {
		NTSTATUS VulnurableDriver::PersistenceFunctions::CleanPiDDBCacheTable(HANDLE* DeviceHandle, PVOID KernelBaseAddress,
			PVOID* RelativePiDDBLock, PVOID* RelativePiDDBCacheTable);  // PiDDBCacheTable is added for driver service when loading
	}
	NTSTATUS LoadVulnurableDriver(HANDLE* VulnHandle, LPCWSTR VulnDriverName, const char* SymbolicLink, const char* ServiceName, const BYTE DriverData[]);
}


namespace VulnurableService {
	NTSTATUS UnloadVulnurableDriver(HANDLE* VulnHandle, char VulnDriverPath[], const char* ServiceName);
	NTSTATUS RegisterVulnurableDriver(char VulnDriverPath[], const char* ServiceName);
	NTSTATUS StartVulnurableDriver(const char* ServiceName);
}