#include <winternl.h>
#include "problematic.h"

NTSTATUS NtQueryProcess(HANDLE ProcessHandle, PROCESSINFOCLASS InfoClass, PVOID Buffer, ULONG InitialSize, PULONG NeededSize) {
	return NtQueryInformationProcess(ProcessHandle, InfoClass, Buffer, InitialSize, NeededSize);
}