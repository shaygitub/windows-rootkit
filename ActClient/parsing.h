#pragma once
#include "structs.h"


/*
==================================================
PARSING DATA AND BUFFERS USED FOR DIFFERENT STUFF:
==================================================
*/


// Parsing main data from an EPROCESS:
void ParseEprocess(BYTE ProcessData[EPROCESS_SIZE]);


// Parsing ROOTKIT_STATUS return status:
void PrintStatusCode(ROOTKIT_STATUS status_code);
void GetBufferValue(PVOID Src, PVOID Dst, SIZE_T Size);
void PrintUnexpected(ROOTKIT_UNEXERR Err);
void PrintInitSystemInfo(SYSTEM_INFO TargetSysInfo);

// Parsing data and buffers returned from system information requests:
void GetBufferValue(PVOID Src, PVOID Dst, SIZE_T Size);
void PrintRegistryData(PVOID RegData, ULONG64 EntrySize);
void PrintBasicSystemInfo(PVOID BasicInfo, ULONG64 EntrySize, char* ProcessorsNum);
void PrintSystemPerformanceInfo(PVOID PerfInfo, BOOL Verbose, ULONG64 EntrySize);
void PrintTimeOfDayInfo(PVOID TimeOfDayInfo, ULONG64 EntrySize);
void PrintWorkingProcessesInfo(PVOID CurrentProcInfo, ULONG64 EntrySize);
void PrintCpuPerformanceInfo(PVOID CpuInf, ULONG64 EntrySize, char* ProcessorsNum);
void PrintInterruptInfo(PVOID IntInf, ULONG64 EntrySize, char* ProcessorsNum);
void PrintExceptionInfo(PVOID ExcInf, ULONG64 EntrySize);
void PrintModulesInfo(PVOID MdlInf, ULONG64 EntrySize);
void PrintLookasideInfo(PVOID LookasdInfo, ULONG64 EntrySize);
void PrintCodeIntgrInfo(PVOID CodeintgrInfo, ULONG64 EntrySize);
void PrintPolicyInfo(PVOID PolicyInfo, ULONG64 EntrySize);
void PrintSystemInformation(PVOID Response, char c, ULONG64 status, DWORD n, ULONG64 Size, char* ProcessorsNum);
SYSTEM_INFORMATION_CLASS ReturnSystemInfo(char InfoType);  // return the specific SYSTEM_INFORMATION_CLASS required for the operation