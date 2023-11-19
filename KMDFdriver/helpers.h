#pragma once
#include "memory.h"

namespace general {
	BOOL FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize);  // frees memory that was allocated during writing/by CommitMemoryRegionsADD
	PVOID AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits);  // allocate memory by parameters (assumes: already attached)
	ULONG64 GetHighestUserModeAddrADD();  // retrieves the maximum usermode address for the local machine
	NTSTATUS ExitRootkitRequestADD(PEPROCESS From, PEPROCESS To, ROOTKIT_STATUS StatusCode, NTSTATUS Status, ROOTKIT_MEMORY* RootkInst);  // general function to exit gracefully from a request
}

namespace requests {
	RKSYSTEM_INFORET RequestSystemInfoADD(SYSTEM_INFORMATION_CLASS InfoType, ULONG64 Flag, DWORD SysInfNum);  // request specific system information (part 1)
	SIZE_T GetExpectedInfoSizeADD(SYSTEM_INFORMATION_CLASS InfoType);  // returns the expected system information buffer size needed for the query, only if the first call to get required size does not work
}