#pragma once
#include <ntifs.h>
#include <ntddk.h>
#include <wdm.h>
#include <minwindef.h>
#pragma comment(lib, "ntoskrnl.lib")


/*
=====================
REQUIRED DEFINITIONS:
=====================
*/


// ZwQuerySystemInformation return structures -
typedef struct _SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION {
	LARGE_INTEGER IdleTime;
	LARGE_INTEGER KernelTime;
	LARGE_INTEGER UserTime;
	LARGE_INTEGER Reserved1[2];
	ULONG Reserved2;
} SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION, * PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
	ULONG NextEntryOffset;
	ULONG NumberOfThreads;
	BYTE Reserved1[48];
	UNICODE_STRING ImageName;
	KPRIORITY BasePriority;
	HANDLE UniqueProcessId;
	PVOID Reserved2;
	ULONG HandleCount;
	ULONG SessionId;
	PVOID Reserved3;
	SIZE_T PeakVirtualSize;
	SIZE_T VirtualSize;
	ULONG Reserved4;
	SIZE_T PeakWorkingSetSize;
	SIZE_T WorkingSetSize;
	PVOID Reserved5;
	SIZE_T QuotaPagedPoolUsage;
	PVOID Reserved6;
	SIZE_T QuotaNonPagedPoolUsage;
	SIZE_T PagefileUsage;
	SIZE_T PeakPagefileUsage;
	SIZE_T PrivatePageCount;
	LARGE_INTEGER Reserved7[6];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef struct _SYSTEM_THREAD_INFORMATION {
	LARGE_INTEGER Reserved1[3];
	ULONG Reserved2;
	PVOID StartAddress;
	CLIENT_ID ClientId;
	KPRIORITY Priority;
	LONG BasePriority;
	ULONG Reserved3;
	ULONG ThreadState;
	ULONG WaitReason;
} SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_REGISTRY_QUOTA_INFORMATION {
	ULONG RegistryQuotaAllowed;
	ULONG RegistryQuotaUsed;
	PVOID Reserved1;
} SYSTEM_REGISTRY_QUOTA_INFORMATION, * PSYSTEM_REGISTRY_QUOTA_INFORMATION;

typedef struct _SYSTEM_BASIC_INFORMATION {
	BYTE Reserved1[24];
	PVOID Reserved2[4];
	CCHAR NumberOfProcessors;
} SYSTEM_BASIC_INFORMATION, * PSYSTEM_BASIC_INFORMATION;

typedef struct _SYSTEM_TIMEOFDAY_INFORMATION {
	BYTE Reserved1[48];
} SYSTEM_TIMEOFDAY_INFORMATION, * PSYSTEM_TIMEOFDAY_INFORMATION;

typedef struct _SYSTEM_PERFORMANCE_INFORMATION {
	BYTE Reserved1[312];
} SYSTEM_PERFORMANCE_INFORMATION, * PSYSTEM_PERFORMANCE_INFORMATION;

typedef struct _SYSTEM_EXCEPTION_INFORMATION {
	BYTE Reserved1[16];
} SYSTEM_EXCEPTION_INFORMATION, * PSYSTEM_EXCEPTION_INFORMATION;

typedef struct _SYSTEM_LOOKASIDE_INFORMATION {
	BYTE Reserved1[32];
} SYSTEM_LOOKASIDE_INFORMATION, * PSYSTEM_LOOKASIDE_INFORMATION;

typedef struct _SYSTEM_INTERRUPT_INFORMATION {
	BYTE Reserved1[24];
} SYSTEM_INTERRUPT_INFORMATION, * PSYSTEM_INTERRUPT_INFORMATION;

typedef struct _SYSTEM_POLICY_INFORMATION {
	PVOID Reserved1[2];
	ULONG Reserved2[3];
} SYSTEM_POLICY_INFORMATION, * PSYSTEM_POLICY_INFORMATION;

typedef struct _SYSTEM_CODEINTEGRITY_INFORMATION {
	ULONG   Length;
	ULONG   CodeIntegrityOptions;
} SYSTEM_CODEINTEGRITY_INFORMATION, * PSYSTEM_CODEINTEGRITY_INFORMATION;


// data about a specific module from a process (i.e an DLL imported in the process) -
typedef struct _RTL_PROCESS_MODULE_INFORMATION
{
	HANDLE Section;
	PVOID MappedBase;
	PVOID ImageBase;
	ULONG ImageSize;
	ULONG Flags;
	USHORT LoadOrderIndex;
	USHORT InitOrderIndex;
	USHORT LoadCount;
	USHORT OffsetToFileName;
	UCHAR  FullPathName[256];
} RTL_PROCESS_MODULE_INFORMATION, * PRTL_PROCESS_MODULE_INFORMATION;

// data about all DLLs (loaded modules) of a specific process, returned in ZwQuerySystemInformation with SystemModuleInformation -
typedef struct _RTL_PROCESS_MODULES
{
	ULONG NumberOfModules;
	RTL_PROCESS_MODULE_INFORMATION Modules[1];
} RTL_PROCESS_MODULES, * PRTL_PROCESS_MODULES;


// SYSTEM_INFORMATION_CLASS definitions for ZwQuerySystemInformation -
typedef enum _SYSTEM_INFORMATION_CLASS {
	SystemBasicInformation = 0,
	SystemPerformanceInformation = 2,
	SystemTimeOfDayInformation = 3,
	SystemProcessInformation = 5,
	SystemProcessorPerformanceInformation = 8,
	SystemInterruptInformation = 23,
	SystemExceptionInformation = 33,
	SystemRegistryQuotaInformation = 37,
	SystemLookasideInformation = 45,
	SystemCodeIntegrityInformation = 103,
	SystemPolicyInformation = 134,
	SystemModuleInformation = 0x0B,
} SYSTEM_INFORMATION_CLASS;


/*
============================
DEPENDENCIES OF MAIN STRUCT:
============================
*/


typedef enum _ROOTKIT_STATUS {
	ROOTKSTATUS_SUCCESS = 0xFF000000,
	ROOTKSTATUS_SYSTEMSPC = 0xFF000001,
	ROOTKSTATUS_PRCPEB = 0xFF000002,
	ROOTKSTATUS_PRCLOADMDLS = 0xFF000003,
	ROOTKSTATUS_OTHER = 0xFF000004,
	ROOTKSTATUS_ADRBUFSIZE = 0xFF000005,
	ROOTKSTATUS_QUERYVIRTMEM = 0xFF000006,
	ROOTKSTATUS_INVARGS = 0xFF000007,
	ROOTKSTATUS_PROTECTIONSTG = 0xFF000008,
	ROOTKSTATUS_NOWRITEPRMS = 0xFF000009,
	ROOTKSTATUS_COPYFAIL = 0x0000000A,
	ROOTKSTATUS_LESSTHNREQ = 0xFF00000B,
	ROOTKSTATUS_MEMALLOC = 0xFF00000C,
	ROOTKSTATUS_NOTCOMMITTED = 0xFF00000D,
	ROOTKSTATUS_QUERYSYSINFO = 0xFF00000E,
	ROOTKSTATUS_PROCHANDLE = 0xFF00000F,
	ROOTKSTATUS_ACSVIO = 0xFF000010,
	ROOTKSTATUS_NOTSUPPORTED = 0xFF000011,
	ROOTKSTATUS_NOTINRELRANGE = 0xFF000012,
	ROOTKSTATUS_PROCESSEPRC = 0XFF000013,
}ROOTKIT_STATUS, * PROOTKIT_STATUS;


typedef enum _ROOTKIT_OPERATION {
	timereq = 0xbbbbff3f,
	random = 0xbbbbf3ff,
	echo = 0xbbbb3fff,
	medata = 0xbbbbfff3,
	null = 0xbbbbbbbb,
	terminatereq = 0xfbfbbfbf,

	RKOP_WRITE = 0x0B0B3456,
	RKOP_READ = 0x0B0B1234,
	RKOP_MDLBASE = 0x0B0B6789,
	RKOP_DSPSTR = 0x0B0B6666,
	RKOP_SYSINFO = 0x0B0B5454,
	RKOP_PRCMALLOC = 0XBB00BB00,

	RKOP_NOOPERATION = 0x0B0B9420,
	RKOP_TERMINATE = 0X0B0BB0B0,
}ROOTKIT_OPERATION, * PROOTKIT_OPERATION;


typedef enum _ROOTKIT_UNEXERR {
	successful = 0x7F7F0000,
	memalloc = 0x7F7F0001,
	relevantpid = 0x7F7F0002,
	receivedata = 0x7F7F0003,
	sendmessage = 0x7F7F0004,
	invalidargs = 0x7F7F0005,
}ROOTKIT_UNEXERR, * PROOTKIT_UNEXERR;


// Struct about passing data on system information -
typedef struct _RKSYSTEM_INFORMATION_CLASS {
	SYSTEM_INFORMATION_CLASS InfoType;
	ULONG InfoSize;
	ROOTKIT_STATUS ReturnStatus;
	PVOID PoolBuffer;
} RKSYSTEM_INFORMATION_CLASS, * PRKSYSTEM_INFORMATION_CLASS;


/*
============
MAIN STRUCT:
============
*/


typedef struct _ROOTKIT_MEMORY {  // Used for communicating with the KM driver
	NTSTATUS Status;  // gets filled by the driver when the operation ends
	ROOTKIT_STATUS StatusCode;  // explains what the status means and why it is what it is
	ROOTKIT_OPERATION Operation;  // what operation to do (by defines)
	PVOID Buffer;  // buffer address (used for example in inputs)
	PVOID Out;  // pointer in memory to the output of the memory function
	ULONG64 Size; // size of memory chunk
	USHORT MainPID; // process that works on the memory
	USHORT SemiPID;  // (if the operation requests for reading) what is the PID of the destination process?
	const char* MdlName;  // (if the operation requests for a module base) what is the name of the module?
	const char* DstMdlName;  // (if the operation requests for a module base) what is the name of the module?
	ROOTKIT_UNEXERR Unexpected;  // data about an unexpected error that happened during the operation, is not relevant to driver
	BOOL IsFlexible;  // specifies if operations can be flexible
	PVOID Reserved;  // used for extra parameters needed to function
}ROOTKIT_MEMORY;


/*
======================================
STRUCTS FOR SPECIFIC USAGE (NOT ALOT):
======================================
*/


// Struct used for return of request system info (level one return type) -
typedef struct _RKSYSTEM_INFORET {
	ULONG64 BufferSize;
	PVOID Buffer;
} RKSYSTEM_INFORET;


/*
================================================
DEPENDENCIES OF IMPLEMENTATION / FUNCTION USAGE:
================================================
*/


// data about an about-to-run/running usermode process (not used currently) -
typedef struct _RTL_USER_PROCESS_PARAMETERS {
	BYTE Reserved1[16];
	PVOID Reserved2[10];
	UNICODE_STRING ImagePathName;
	UNICODE_STRING CommandLine;
} RTL_USER_PROCESS_PARAMETERS, * PRTL_USER_PROCESS_PARAMETERS;


// the Process Environment Block loading data (data about used DLLs and other info for the loader, used in requests.cpp::GetModuleBase64bit and in _PEB struct) -
typedef struct _PEB_LDR_DATA {
	ULONG Length;
	BOOLEAN Initialized;
	PVOID SsHandle;
	LIST_ENTRY ModuleListLoadOrder;
	LIST_ENTRY ModuleListMemoryOrder;
	LIST_ENTRY ModuleListInitOrder;
} PEB_LDR_DATA, * PPEB_LDR_DATA;


// same as _PEB_LDR_DATA but for processes running on 32bit architecture (not used currently) -
typedef struct _PEB_LDR_DATA32
{
	ULONG Length;
	UCHAR Initialized;
	ULONG SsHandle;
	LIST_ENTRY32 InLoadOrderModuleList;
	LIST_ENTRY32 InMemoryOrderModuleList;
	LIST_ENTRY32 InInitializationOrderModuleList;
} PEB_LDR_DATA32, * PPEB_LDR_DATA32;


typedef void(__stdcall* PPS_POST_PROCESS_INIT_ROUTINE)(void); // not exported, used in _PEB structure


// data about the Process Environment Block of a specific process (includes important data about a running process, used in requests.cpp::GetModuleBase64bit) -
typedef struct _PEB {
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PPS_POST_PROCESS_INIT_ROUTINE PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, * PPEB;


// same as _PEB but for 32bit architecture (not currently used) -
typedef struct _PEB32
{
	UCHAR InheritedAddressSpace;
	UCHAR ReadImageFileExecOptions;
	UCHAR BeingDebugged;
	UCHAR BitField;
	ULONG Mutant;
	ULONG ImageBaseAddress;
	ULONG Ldr;
	ULONG ProcessParameters;
	ULONG SubSystemData;
	ULONG ProcessHeap;
	ULONG FastPebLock;
	ULONG AtlThunkSListPtr;
	ULONG IFEOKey;
	ULONG CrossProcessFlags;
	ULONG UserSharedInfoPtr;
	ULONG SystemReserved;
	ULONG AtlThunkSListPtr32;
	ULONG ApiSetMap;
} PEB32, * PPEB32;


// data about a specific module inside the loaded module (DLL) list of a specific process, appears as a part of a linked list somewhere in _PEB_LDR_DATA -
typedef struct _LDR_DATA_TABLE_ENTRY {
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;  // in bytes
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	ULONG Flags;  // LDR_*
	USHORT LoadCount;
	USHORT TlsIndex;
	LIST_ENTRY HashLinks;
	PVOID SectionPointer;
	ULONG CheckSum;
	ULONG TimeDateStamp;
	//    PVOID			LoadedImports;
	//    // seems they are exist only on XP !!! PVOID
	//    EntryPointActivationContext;	// -same-
} LDR_DATA_TABLE_ENTRY, * PLDR_DATA_TABLE_ENTRY;


// Protect a chunk of virtual memory -
extern "C" __declspec(dllimport) NTSTATUS NTAPI ZwProtectVirtualMemory
(
	HANDLE ProcessHandle,
	PVOID * BaseAddress,
	PULONG ProtectSize,
	ULONG NewProtect,
	PULONG OldProtect
);


// Copy virtual memory from one process into another process (can also be used in KM with PeGetCurrentProcess as the PEPROCESS) -
extern "C" NTSTATUS NTAPI MmCopyVirtualMemory 
(
	PEPROCESS SourceProcess,
	PVOID SourceAddress,
	PEPROCESS TargetProcess,
	PVOID TargetAddress,
	SIZE_T BufferSize,
	KPROCESSOR_MODE PreviousMode,
	PSIZE_T ReturnSize
);


// Find a routine (function) from a module (dll, sys...) with the routine's name -
extern "C" NTKERNELAPI PVOID NTAPI RtlFindExportedRoutineByName(_In_ PVOID ImageBase, _In_ PCCH RoutineName);

// Get information about the system on a specific topic (InfoClass) -
extern "C" NTSTATUS ZwQuerySystemInformation(ULONG InfoClass, PVOID Buffer, ULONG Length, PULONG ReturnLength);

// Get the PEB of a process -
extern "C" NTKERNELAPI PPEB PsGetProcessPeb(IN PEPROCESS Process);