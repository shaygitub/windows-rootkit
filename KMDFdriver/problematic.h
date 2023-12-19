#pragma once
NTSTATUS NtQueryProcess(HANDLE ProcessHandle, PROCESSINFOCLASS InfoClass, PVOID Buffer, ULONG InitialSize, PULONG NeededSize);