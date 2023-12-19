#pragma once
#include "memory.h"


// Memory functions pool structure is 'Hl..'
namespace general {
	BOOL FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize);  // frees memory that was allocated during writing/by CommitMemoryRegionsADD
	PVOID AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits);  // allocate memory by parameters (assumes: already attached)
	ULONG64 GetHighestUserModeAddrADD();  // retrieves the maximum usermode address for the local machine
	NTSTATUS ExitRootkitRequestADD(PEPROCESS From, PEPROCESS To, ROOTKIT_STATUS StatusCode, NTSTATUS Status, ROOTKIT_MEMORY* RootkInst);  // general function to exit gracefully from a request
	NTSTATUS OpenProcessHandleADD(HANDLE* Process, USHORT PID);  // Get process handle with PID of the process
	NTSTATUS CopyStringAfterCharADD(PUNICODE_STRING OgString, PUNICODE_STRING NewString, WCHAR Char);  // Copy substring after last apearance of defined character
	BOOL CompareUnicodeStringsADD(PUNICODE_STRING First, PUNICODE_STRING Second, USHORT CheckLength);  // Compare two unicode strings
	BOOL IsExistFromIndexADD(PUNICODE_STRING Inner, PUNICODE_STRING Outer, USHORT StartIndex);  // Find inner in outer from start index
}
namespace requests {
	RKSYSTEM_INFORET RequestSystemInfoADD(SYSTEM_INFORMATION_CLASS InfoType, ULONG64 Flag);  // request specific system information (part 1)
	SIZE_T GetExpectedInfoSizeADD(SYSTEM_INFORMATION_CLASS InfoType);  // returns the expected system information buffer size needed for the query, only if the first call to get required size does not work
}