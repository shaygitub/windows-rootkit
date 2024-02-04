#include "parsing.h"
#pragma warning( disable : 4302 )
#pragma warning( disable : 4311 )

/*
==================================================
PARSING DATA AND BUFFERS USED FOR DIFFERENT STUFF:
==================================================
*/


// Parsing main data from an EPROCESS:
void ParseEprocess(BYTE ProcessData[EPROCESS_SIZE]) {
	ULONG64 CurrentProcessId = 0;
	ULONG64 BeforeVirtualSize = 0;
	ULONG64 PeakVirtualSize = 0;
	ULONG64 CurrentCookie = 0;
	ULONG64 CurrentOwnerProcessId = 0;
	ULONG64 PageDirectoryPte = 0;
	BYTE CurrentPriorityClass = 0;
	char CurrentImageName[15] = { 0 };
	PVOID CurrentHighestUsermodeAddress = NULL;
	ULONG CurrentActiveThreads = 0;
	ULONG LastThreadExitStatus = 0;
	ULONG CurrentExitStatus = 0;
	ULONG CurrentFlags = 0;
	LARGE_INTEGER CurrentReadCount = { 0 };
	LARGE_INTEGER CurrentWriteCount = { 0 };
	LARGE_INTEGER CurrentOtherCount = { 0 };
	LARGE_INTEGER CurrentCreateTime = { 0 };


	// Parsing actual data:
	RtlCopyMemory(&CurrentProcessId, (PVOID)((ULONG64)ProcessData + EPOF_UniqueProcessId), sizeof(CurrentProcessId));
	RtlCopyMemory(&BeforeVirtualSize, (PVOID)((ULONG64)ProcessData + EPOF_VirtualSize), sizeof(BeforeVirtualSize));
	RtlCopyMemory(&PeakVirtualSize, (PVOID)((ULONG64)ProcessData + EPOF_PeakVirtualSize), sizeof(PeakVirtualSize));
	RtlCopyMemory(&CurrentCookie, (PVOID)((ULONG64)ProcessData + EPOF_Cookie), sizeof(CurrentCookie));
	RtlCopyMemory(&CurrentOwnerProcessId, (PVOID)((ULONG64)ProcessData + EPOF_OwnerProcessId), sizeof(CurrentOwnerProcessId));
	RtlCopyMemory(&PageDirectoryPte, (PVOID)((ULONG64)ProcessData + EPOF_PageDirectoryPte), sizeof(PageDirectoryPte));
	RtlCopyMemory(&CurrentPriorityClass, (PVOID)((ULONG64)ProcessData + EPOF_PriorityClass), sizeof(CurrentPriorityClass));
	RtlCopyMemory(CurrentImageName, (PVOID)((ULONG64)ProcessData + EPOF_ImageFileName), 15);
	RtlCopyMemory(&CurrentHighestUsermodeAddress, (PVOID)((ULONG64)ProcessData + EPOF_HighestUserAddress), sizeof(CurrentHighestUsermodeAddress));
	RtlCopyMemory(&CurrentActiveThreads, (PVOID)((ULONG64)ProcessData + EPOF_ActiveThreads), sizeof(CurrentActiveThreads));
	RtlCopyMemory(&LastThreadExitStatus, (PVOID)((ULONG64)ProcessData + EPOF_LastThreadExitStatus), sizeof(LastThreadExitStatus));
	RtlCopyMemory(&CurrentExitStatus, (PVOID)((ULONG64)ProcessData + EPOF_ExitStatus), sizeof(CurrentExitStatus));
	RtlCopyMemory(&CurrentFlags, (PVOID)((ULONG64)ProcessData + EPOF_Flags), sizeof(CurrentFlags));
	RtlCopyMemory(&CurrentReadCount, (PVOID)((ULONG64)ProcessData + EPOF_ReadOperationCount), sizeof(CurrentReadCount));
	RtlCopyMemory(&CurrentWriteCount, (PVOID)((ULONG64)ProcessData + EPOF_WriteOperationCount), sizeof(CurrentWriteCount));
	RtlCopyMemory(&CurrentOtherCount, (PVOID)((ULONG64)ProcessData + EPOF_OtherOperationCount), sizeof(CurrentOtherCount));
	RtlCopyMemory(&CurrentCreateTime, (PVOID)((ULONG64)ProcessData + EPOF_CreateTime), sizeof(CurrentCreateTime));


	// Print parsed data:
	printf("Process ID: %llu\n"
		"\"Current\" virtual size: %llu\n"
		"Peak virtual size: %llu\n"
		"Process cookie: %llu\n"
		"Owner process ID: %llu\n"
		"Page directory PTE: %llu\n"
		"Priority class: %hhu\n"
		"Process image name: %s\n"
		"Highest usermode address: %p\n"
		"Active threads: %lu\n"
		"Last thread exit status: %lu\n"
		"Process exit status: %lu\n"
		"Process flags: %lu\n"
		"Read operations count: %llu\n"
		"Write operations count: %llu\n"
		"Other operations count: %llu\n"
		"Process start time: %llu\n", CurrentProcessId, BeforeVirtualSize, PeakVirtualSize, CurrentCookie, CurrentOwnerProcessId, PageDirectoryPte, CurrentPriorityClass, CurrentImageName, CurrentHighestUsermodeAddress, CurrentActiveThreads, LastThreadExitStatus, CurrentExitStatus, CurrentFlags, CurrentReadCount.QuadPart, CurrentWriteCount.QuadPart, CurrentOtherCount.QuadPart, CurrentCreateTime.QuadPart);
}


// Parsing ROOTKIT_STATUS return status:
void PrintStatusCode(ROOTKIT_STATUS status_code) {
	switch (status_code) {
	case ROOTKSTATUS_SYSTEMSPC: printf("Operation FAILED - tried to access system memory area of virtual address space\n"); break;
	case ROOTKSTATUS_PRCPEB: printf("Operation FAILED - failed using a required process PEB for the operation\n"); break;
	case ROOTKSTATUS_PRCLOADMDLS: printf("Operation FAILED - process has no loaded modules, cannot get its base (LDR = NULL)\n"); break;
	case ROOTKSTATUS_OTHER: printf("Operation FAILED - an error occurred that is either general/not included in the other errors\n"); break;
	case ROOTKSTATUS_ADRBUFSIZE: printf("Operation FAILED - impossible (possibly NULL) values for address/es / buffer/s / size/s\n"); break;
	case ROOTKSTATUS_QUERYVIRTMEM: printf("Operation FAILED - a required query of the relevant virtual memory has failed\n"); break;
	case ROOTKSTATUS_INVARGS: printf("Operation FAILED - invalid argument/s were supplied for the operation\n"); break;
	case ROOTKSTATUS_PROTECTIONSTG: printf("Operation FAILED - protection settings of relevant memory stopped the operation\n"); break;
	case ROOTKSTATUS_NOWRITEPRMS: printf("Operation FAILED - could not write to memory because memory is not writeable\n"); break;
	case ROOTKSTATUS_COPYFAIL: printf("Operation FAILED - could not copy memory from one address to another (virtual/physical)\n"); break;
	case ROOTKSTATUS_LESSTHNREQ: printf("Operation OK - operation succeeded but the size written/copied to memory < requested size\n"); break;
	case ROOTKSTATUS_MEMALLOC: printf("Operation FAILED - could not allocate a required memory buffer\n"); break;
	case ROOTKSTATUS_NOTCOMMITTED: printf("Operation FAILED - requested memory area is not committed (not in actual physical memory)\n"); break;
	case ROOTKSTATUS_PROCHANDLE: printf("Operation FAILED - a required process handle could not be achieved by driver\n"); break;
	case ROOTKSTATUS_ACSVIO: printf("Operation FAILED - an access violation occurred while performing the operation\n"); break;
	case ROOTKSTATUS_NOTSUPPORTED: printf("Operation FAILED - status of operation is not supported by machine\n"); break;
	case ROOTKSTATUS_NOTINRELRANGE: printf("Operation FAILED - an address (mainly) / other value was passed that is not in the relative range for the operation\n"); break;
	case ROOTKSTATUS_PROCESSEPRC: printf("Operation FAILED - driver could not get the EPROCESS of a relevant process/processes\n"); break;
	default: printf("Operation SUCCEES\n");
	}
	printf("\n");
}


// Copy the data from a certain place in a buffer -
void GetBufferValue(PVOID Src, PVOID Dst, SIZE_T Size) {
	memcpy(Dst, Src, Size);
}


// Parse unexpected error values -
void PrintUnexpected(ROOTKIT_UNEXERR Err) {
	switch (Err) {
	case relevantpid: printf("Unexpected error occurred - medium could not required a PID relevant to the operation\n"); break;

	case memalloc: printf("Unexpected error occurred - medium could not allocate required memory for the operation\n"); break;

	case receivedata: printf("Unexpected error occurred - medium could not receive operation information from client\n"); break;

	case sendmessage: printf("Unexpected error occurred - medium could not send operation information to client\n"); break;

	case invalidargs: printf("Unexpected error occurred - medium was given invalid arguments from client\n"); break;

	default: printf("Unexpected error DID NOT OCCUR (for now, if more data needs to be received, be ready for additional checks about errors after sending the struct)\n"); break;

	}
}


// Print basic system information that is received when connection is initiated -
void PrintInitSystemInfo(SYSTEM_INFO TargetSysInfo) {
	printf("Number of processors on target (DWORD) - %lu\n", TargetSysInfo.dwNumberOfProcessors);
	printf("Page size on target (DWORD) - %lu\n", TargetSysInfo.dwPageSize);
	printf("Allocation granularity on target (DWORD) - %lu\n", TargetSysInfo.dwAllocationGranularity);
	printf("Active processor mask on target (DWORD_PTR, converted to PVOID) - %p\n", (PVOID)TargetSysInfo.dwActiveProcessorMask);
	printf("OemID on target (DWORD) - %lu\n", TargetSysInfo.dwOemId);
	printf("Processor type on target (DWORD) - %lu\n", TargetSysInfo.dwProcessorType);
	printf("Maximum UM VA on target (LPVOID) - %p\n", TargetSysInfo.lpMaximumApplicationAddress);
	printf("Minimum UM VA on target (LPVOID) - %p\n", TargetSysInfo.lpMinimumApplicationAddress);
	printf("Processor Architecture on target (WORD/USHORT) - %hu\n", TargetSysInfo.wProcessorArchitecture);
	printf("Processor level on target (WORD/USHORT) - %hu\n", TargetSysInfo.wProcessorLevel);
	printf("Processor revision on target (WORD/USHORT) - %hu\n", TargetSysInfo.wProcessorRevision);
	printf("wReserved value on target (WORD/USHORT) - %hu\n", TargetSysInfo.wReserved);
}


// Parsing data and buffers returned from system information requests:
// Different singular functions for each type -
// Print registry data from target -
void PrintRegistryData(PVOID RegData, ULONG64 EntrySize) {
	SYSTEM_REGISTRY_QUOTA_INFORMATION Regd;
	memcpy(&Regd, RegData, sizeof(SYSTEM_REGISTRY_QUOTA_INFORMATION));
	printf("Registry quota data of target:\n");
	printf("  Registry quota allowed amount ULONG -> %lu\n", Regd.RegistryQuotaAllowed);
	printf("  Registry quota used amount ULONG -> %lu\n", Regd.RegistryQuotaUsed);
	printf("  Size of a paged pool PVOID -> %p\n", Regd.Reserved1);
}


// Print basic information on target -
void PrintBasicSystemInfo(PVOID BasicInfo, ULONG64 EntrySize, char* ProcessorsNum) {
	ULONG unslong = 0;
	ULONG_PTR unslong_ptr = 0;
	CHAR chr = 0;
	SYSTEM_BASIC_INFORMATION Basicinf;
	SYSTEM_INFO TargetSysInfo = { 0 };
	GetSystemInfo(&TargetSysInfo);

	memcpy(&Basicinf, BasicInfo, sizeof(SYSTEM_BASIC_INFORMATION));
	printf("Basic system information from target:\n");
	GetBufferValue(Basicinf.Reserved1, &unslong, sizeof(unslong)); printf("  Reserved ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)Basicinf.Reserved1 + 0x04), &unslong, sizeof(unslong));  printf("  Timer resolution ULONG -> %lu\n", unslong);
	
	GetBufferValue((PVOID)((ULONG64)Basicinf.Reserved1 + 0x08), &unslong, sizeof(unslong));  printf("  Page size ULONG -> %lu (compared to earlier %lu)\n", unslong, (ULONG)TargetSysInfo.dwPageSize);
	GetBufferValue((PVOID)((ULONG64)Basicinf.Reserved1 + 0x0C), &unslong, sizeof(unslong));  printf("  Number of physical pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)Basicinf.Reserved1 + 0x10), &unslong, sizeof(unslong));  printf("  Lowest physical pages number ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)Basicinf.Reserved1 + 0x14), &unslong, sizeof(unslong));  printf("  Highest physical pages number ULONG -> %lu\n", unslong);
	printf("  Allocation granularity of target PVOID -> %p (compared to earlier %lu)\n", Basicinf.Reserved2[0], TargetSysInfo.dwAllocationGranularity);
	printf("  Lowest virtual address of UM program PVOID -> %p (compared to earlier %p)\n", Basicinf.Reserved2[1], TargetSysInfo.lpMinimumApplicationAddress);
	printf("  Highest virtual address of UM program PVOID -> %p (compared to earlier %p)\n", Basicinf.Reserved2[2], TargetSysInfo.lpMaximumApplicationAddress);
	printf("  Active processors affinity mask PVOID -> %p\n", Basicinf.Reserved2[3]);
	printf("  Number of physical processing units on target CHAR -> %u (number of virtual processing units: %u)\n", Basicinf.NumberOfProcessors, (CCHAR)TargetSysInfo.dwNumberOfProcessors);
	memcpy(ProcessorsNum, &Basicinf.NumberOfProcessors, sizeof(CCHAR));  // update the number of processors on the target system
}


// Print system performance info of target -
void PrintSystemPerformanceInfo(PVOID PerfInfo, BOOL Verbose, ULONG64 EntrySize) {
	LARGE_INTEGER largeint = { 0 };
	ULONG unslong = 0;
	SYSTEM_PERFORMANCE_INFORMATION* SysPerfInf = (SYSTEM_PERFORMANCE_INFORMATION*)PerfInfo;

	printf("System Performance of target:\n");
	GetBufferValue(SysPerfInf->Reserved1, &largeint, sizeof(largeint));  printf("  Idle process time LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x08), &largeint, sizeof(largeint)); printf("  IO read transfer count LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x10), &largeint, sizeof(largeint)); printf("  IO write transfer count LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x18), &largeint, sizeof(largeint)); printf("  IO other transfer count LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x20), &unslong, sizeof(unslong));  printf("  Total number of IO read operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x24), &unslong, sizeof(unslong)); printf("  Total number of IO write operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x28), &unslong, sizeof(unslong)); printf("  Total number of IO other operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x2C), &unslong, sizeof(unslong)); printf("  Total number of available pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x30), &unslong, sizeof(unslong)); printf("  Total number of committed pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x34), &unslong, sizeof(unslong)); printf("  Limit of committed pages at one time ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x38), &unslong, sizeof(unslong)); printf("  Peak commitment amount ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x3C), &unslong, sizeof(unslong)); printf("  Total number of page faults ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x40), &unslong, sizeof(unslong)); printf("  Total number copy-on-write operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x44), &unslong, sizeof(unslong)); printf("  Total number of transitions ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x48), &unslong, sizeof(unslong)); printf("  Total number of cache transitions ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x4C), &unslong, sizeof(unslong)); printf("  Total number of demand-zero operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x50), &unslong, sizeof(unslong)); printf("  Total number of read operations from a page ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x54), &unslong, sizeof(unslong)); printf("  Total number of IO<->page read operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x58), &unslong, sizeof(unslong)); printf("  Total number of cache read operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x5C), &unslong, sizeof(unslong)); printf("  Total number of cache<->IO operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x60), &unslong, sizeof(unslong)); printf("  Total number of dirty pages write operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x64), &unslong, sizeof(unslong)); printf("  Total number of dirty pages<->IO write operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x68), &unslong, sizeof(unslong)); printf("  Total number of mapped pages write operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x6C), &unslong, sizeof(unslong)); printf("  Total number of mapped pages<->IO write operations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x70), &unslong, sizeof(unslong)); printf("  Total number of pages that are a part of paged pools ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x74), &unslong, sizeof(unslong)); printf("  Total number of pages that are a part of non-paged pools ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x78), &unslong, sizeof(unslong)); printf("  Total number of allocate operations on paged pools ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x7C), &unslong, sizeof(unslong)); printf("  Total number of free operations on paged pools ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x80), &unslong, sizeof(unslong)); printf("  Total number of allocate operations on non-paged pools ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x84), &unslong, sizeof(unslong)); printf("  Total number of free operations on non-paged pools ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x88), &unslong, sizeof(unslong)); printf("  Total number of free system ptes ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x8C), &unslong, sizeof(unslong)); printf("  Total number of resident system code pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x90), &unslong, sizeof(unslong)); printf("  Total number of system driver pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x94), &unslong, sizeof(unslong)); printf("  Total number of system code pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x98), &unslong, sizeof(unslong)); printf("  Total number of non-paged pool lookaside hits ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x9C), &unslong, sizeof(unslong)); printf("  Total number of paged pool lookaside hits ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xA0), &unslong, sizeof(unslong)); printf("  Total number of available paged pool pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xA4), &unslong, sizeof(unslong)); printf("  Total number of resident system cache pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xA8), &unslong, sizeof(unslong)); printf("  Total number of resident paged pool pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xAC), &unslong, sizeof(unslong)); printf("  Total number of resident system driver pages ULONG -> %lu\n", unslong);

	if (!Verbose) {
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xB0), &unslong, sizeof(unslong)); printf("  Total number of IO fast read no waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xB4), &unslong, sizeof(unslong)); printf("  Total number of cc fast read waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xB8), &unslong, sizeof(unslong)); printf("  Total number of cc fast read operations that were given unsufficient resources ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xBC), &unslong, sizeof(unslong)); printf("  Total number of cc fast read operations that were not possible ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xC0), &unslong, sizeof(unslong)); printf("  Total number of cc fast module read no waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xC4), &unslong, sizeof(unslong)); printf("  Total number of cc fast module read waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xC8), &unslong, sizeof(unslong)); printf("  Total number of cc fast module read operations that were given unsufficient resources ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xCC), &unslong, sizeof(unslong)); printf("  Total number of cc fast module read operations that were not possible ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xD0), &unslong, sizeof(unslong)); printf("  Total number cc map data no waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xD4), &unslong, sizeof(unslong)); printf("  Total number cc map data waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xD8), &unslong, sizeof(unslong)); printf("  Total number cc map data no wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xDC), &unslong, sizeof(unslong)); printf("  Total number cc map data wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xE0), &unslong, sizeof(unslong)); printf("  Total number of cc pin mapped data ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xE4), &unslong, sizeof(unslong)); printf("  Total number of cc read pin no waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xE8), &unslong, sizeof(unslong)); printf("  Total number of cc read pin waits -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xEC), &unslong, sizeof(unslong)); printf("  Total number of cc read pin no wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xF0), &unslong, sizeof(unslong)); printf("  Total number of cc read pin wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xF4), &unslong, sizeof(unslong)); printf("  Total number of cc copy-read no waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xF8), &unslong, sizeof(unslong)); printf("  Total number of cc copy-read waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0xFC), &unslong, sizeof(unslong)); printf("  Total number of cc copy-read no wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x100), &unslong, sizeof(unslong)); printf("  Total number of cc copy-read wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x104), &unslong, sizeof(unslong)); printf("  Total number of cc read module no waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x108), &unslong, sizeof(unslong)); printf("  Total number of cc read module waits ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x10C), &unslong, sizeof(unslong)); printf("  Total number of cc read module no wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x110), &unslong, sizeof(unslong)); printf("  Total number of cc read module wait misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x114), &unslong, sizeof(unslong)); printf("  Total number of cc read ahead from IO operations ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x118), &unslong, sizeof(unslong)); printf("  Total number of cc write operations in lazy pages<->IO ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x11C), &unslong, sizeof(unslong)); printf("  Total number of cc write operations in lazy pages ULONG -> %lu\n", unslong);
	}

	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x120), &unslong, sizeof(unslong)); printf("  Total number of cc data flushes ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x124), &unslong, sizeof(unslong)); printf("  Total number of cc data pages ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x128), &unslong, sizeof(unslong)); printf("  Total number of context switches ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x12C), &unslong, sizeof(unslong)); printf("  Total number of 1st level tb fills ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x130), &unslong, sizeof(unslong)); printf("  Total number of 2nd level tb fills ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)SysPerfInf->Reserved1 + 0x134), &unslong, sizeof(unslong)); printf("  Total number of system calls ULONG -> %lu\n", unslong);
}


// Print time of day on target -
void PrintTimeOfDayInfo(PVOID TimeOfDayInfo, ULONG64 EntrySize) {
	ULONG unslong = 0;
	ULONG64 unslonglong = 0;
	LARGE_INTEGER largeint = { 0 };

	SYSTEM_TIMEOFDAY_INFORMATION* TimeInf = (SYSTEM_TIMEOFDAY_INFORMATION*)TimeOfDayInfo;
	GetBufferValue(TimeInf->Reserved1, &largeint, sizeof(largeint)); printf("  Boot time of target LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)TimeInf->Reserved1 + 0x08), &largeint, sizeof(largeint)); printf("  Current time on target LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)TimeInf->Reserved1 + 0x10), &largeint, sizeof(largeint)); printf("  Time zone bias of target LARGE_INTEGER (actual value is LONGLONG)-> %llu\n", largeint.QuadPart);
	GetBufferValue((PVOID)((ULONG64)TimeInf->Reserved1 + 0x18), &unslong, sizeof(unslong)); printf("  Time zone id of target ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)TimeInf->Reserved1 + 0x1C), &unslong, sizeof(unslong));  printf("  Reserved ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)TimeInf->Reserved1 + 0x20), &unslonglong, sizeof(unslonglong));  printf("  Boot time bias of target ULONGLONG -> %llu\n", unslonglong);
	GetBufferValue((PVOID)((ULONG64)TimeInf->Reserved1 + 0x28), &unslonglong, sizeof(unslonglong));  printf("  Sleep time bias of target ULONGLONG -> %llu\n", unslonglong);
}


// Print all working processes on target -
void PrintWorkingProcessesInfo(PVOID CurrentProcInfo, ULONG64 EntrySize) {
	ULONG ProcOffs = 0;
	ULONG ProcCount = 0;
	ULONG ThreadOffs = 0;;
	ULONG unslong = 0;
	ULONGLONG unslonglong = 0;
	LARGE_INTEGER largeint = { 0 };
	SYSTEM_PROCESS_INFORMATION CurrEntry;
	SYSTEM_THREAD_INFORMATION CurrThread;
	memcpy(&CurrEntry, CurrentProcInfo, sizeof(SYSTEM_PROCESS_INFORMATION));

	printf("Working Processes of target:\n");
	while (1 == 1) {
		ProcCount++;

		// Process entry enumeration -
		printf("Process %llu (image name = %wZ) -\n", (ULONG_PTR)CurrEntry.UniqueProcessId, &CurrEntry.ImageName);
		printf("  EXTRA: Entry size ULONG -> %lu\n", CurrEntry.NextEntryOffset - ProcOffs);
		printf("  Next entry offset from this one ULONG -> %lu\n", CurrEntry.NextEntryOffset);
		printf("  Number of threads ULONG -> %lu\n", CurrEntry.NumberOfThreads);
		GetBufferValue(CurrEntry.Reserved1, &largeint, sizeof(largeint));  printf("  Private size of working set LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", largeint.QuadPart);
		GetBufferValue((PVOID)((ULONG64)CurrEntry.Reserved1 + 8), &unslong, sizeof(unslong));  printf("  Hard fault count ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)CurrEntry.Reserved1 + 12), &unslong, sizeof(unslong));  printf("  Number of threads high watermark ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)CurrEntry.Reserved1 + 16), &unslonglong, sizeof(unslonglong));  printf("  Cycle time ULONGLONG -> %llu\n", unslonglong);
		GetBufferValue((PVOID)((ULONG64)CurrEntry.Reserved1 + 24), &largeint, sizeof(largeint));  printf("  Time of creation LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", largeint.QuadPart);
		GetBufferValue((PVOID)((ULONG64)CurrEntry.Reserved1 + 32), &largeint, sizeof(largeint));  printf("  Time of running in usermode LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", largeint.QuadPart);
		GetBufferValue((PVOID)((ULONG64)CurrEntry.Reserved1 + 40), &largeint, sizeof(largeint));  printf("  Time of running in kernel mode LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", largeint.QuadPart);
		printf("  Process base priority LONG -> %lu\n", CurrEntry.BasePriority);
		printf("  Inherited from PID PVOID -> %p\n", CurrEntry.Reserved2);
		printf("  Amount of handles ULONG -> %lu\n", CurrEntry.HandleCount);
		printf("  Session ID ULONG -> %lu\n", CurrEntry.SessionId);
		printf("  Unique process key PVOID -> %p\n", CurrEntry.Reserved3);
		printf("  Peak virtual size SIZE_T -> %llu\n", (ULONG64)CurrEntry.PeakVirtualSize);
		printf("  Current virtual size SIZE_T -> %llu\n", (ULONG64)CurrEntry.VirtualSize);
		printf("  Amount of page faults related to process ULONG -> %lu\n", CurrEntry.Reserved4);
		printf("  Peak working set size SIZE_T -> %llu\n", (ULONG64)CurrEntry.PeakWorkingSetSize);
		printf("  Current working set size SIZE_T -> %llu\n", (ULONG64)CurrEntry.WorkingSetSize);
		printf("  Peak quota paged pool usage PVOID -> %p\n", CurrEntry.Reserved5);
		printf("  Current quota paged pool usage SIZE_T -> %llu\n", (ULONG64)CurrEntry.QuotaPagedPoolUsage);
		printf("  Peak quota non-paged pool usage PVOID -> %p\n", CurrEntry.Reserved6);
		printf("  Current quota non-paged pool usage SIZE_T -> %llu\n", (ULONG64)CurrEntry.QuotaPagedPoolUsage);
		printf("  Peak pagefile usages SIZE_T -> %llu\n", (ULONG64)CurrEntry.PeakPagefileUsage);
		printf("  Current pagefile usages SIZE_T -> %llu\n", (ULONG64)CurrEntry.PagefileUsage);
		printf("  Amount of private (reserved) pages SIZE_T -> %llu\n", (ULONG64)CurrEntry.PrivatePageCount);
		printf("  Current working set size SIZE_T -> %llu\n", (ULONG64)CurrEntry.WorkingSetSize);
		printf("  Amount of read operations LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrEntry.Reserved7[0].QuadPart);
		printf("  Amount of write operations LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrEntry.Reserved7[1].QuadPart);
		printf("  Amount of other operations LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrEntry.Reserved7[2].QuadPart);
		printf("  Amount of read transitions LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrEntry.Reserved7[3].QuadPart);
		printf("  Amount of write transitions LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrEntry.Reserved7[4].QuadPart);
		printf("  Amount of other transitions LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrEntry.Reserved7[5].QuadPart);

		// Threads enumeration -
		memcpy(&CurrThread, (PVOID)((ULONG64)CurrentProcInfo + ProcOffs + sizeof(SYSTEM_PROCESS_INFORMATION) + ThreadOffs), sizeof(SYSTEM_THREAD_INFORMATION));
		printf("Threads of process entry (there are %llu threads active in this process currently) -\n", (ULONG64)(CurrEntry.NextEntryOffset - ProcOffs - sizeof(SYSTEM_PROCESS_INFORMATION)) / sizeof(SYSTEM_THREAD_INFORMATION));
		for (int t = 0; t < (CurrEntry.NextEntryOffset - ProcOffs - sizeof(SYSTEM_PROCESS_INFORMATION)) / sizeof(SYSTEM_THREAD_INFORMATION); t++) {
			printf("  Kernelmode time of thread LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrThread.Reserved1[0].QuadPart);
			printf("  Usermode time of thread LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrThread.Reserved1[1].QuadPart);
			printf("  Creation time of thread LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", CurrThread.Reserved1[2].QuadPart);
			printf("  Current waiting time ULONG -> %lu\n", CurrThread.Reserved2);
			printf("  Start address of thread PVOID -> %p\n", CurrThread.StartAddress);
			printf("  PID of father process of thread PVOID -> %p\n", CurrThread.ClientId.UniqueProcess);
			printf("  TID of thread PVOID -> %p\n", CurrThread.ClientId.UniqueThread);
			printf("  Thread base priority LONG -> %lu\n", CurrThread.BasePriority);
			printf("  Current thread priority LONG -> %lu\n", CurrThread.Priority);
			printf("  Total amount of context switches of thread ULONG -> %lu\n", CurrThread.Reserved3);
			printf("  Thread state ULONG -> %lu\n", CurrThread.ThreadState);
			printf("  Wait reason (if the thread is waiting) ULONG -> %lu\n", CurrThread.WaitReason);
			ThreadOffs += sizeof(SYSTEM_THREAD_INFORMATION);
			memcpy(&CurrThread, (PVOID)((ULONG64)CurrentProcInfo + ProcOffs + sizeof(SYSTEM_PROCESS_INFORMATION) + ThreadOffs), sizeof(SYSTEM_THREAD_INFORMATION));
		}

		ThreadOffs = 0;
		if (CurrEntry.NextEntryOffset == 0) {
			break;
		}

		ProcOffs += CurrEntry.NextEntryOffset - ProcOffs;
		memcpy(&CurrEntry, (PVOID)((ULONG64)CurrentProcInfo + ProcOffs), sizeof(SYSTEM_PROCESS_INFORMATION));
	}
	printf("TOTAL AMOUNT OF RUNNING PROCESSES WHEN CALLING -> %lu\n", ProcCount);
}


// Print cpu performance of target -
void PrintCpuPerformanceInfo(PVOID CpuInf, ULONG64 EntrySize, char* ProcessorsNum) {
	ULONG ProcssOffs = 0;
	SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION Procssinf;

	printf("CPU Performance of target:\n");
	memcpy(&Procssinf, CpuInf, sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION));
	for (ULONG i = 0; i < (ULONG)*ProcessorsNum; i++) {
		printf("Processor number %lu -\n", i + 1);
		printf("  Total kernelmode processing time of processor LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", Procssinf.KernelTime.QuadPart);
		printf("  Total usermode processing time of processor LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", Procssinf.UserTime.QuadPart);
		printf("  Total idle time of processor LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", Procssinf.IdleTime.QuadPart);
		printf("  Total time of processor interrupts used in processor LARGE_INTEGER (actual value is LONGLONG) -> %llu\n", Procssinf.Reserved1->QuadPart);
		printf("  Total amount of processor interrupts used in processor ULONG -> %lu\n", Procssinf.Reserved2);
		ProcssOffs += sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION);
		memcpy(&Procssinf, (PVOID)((ULONG64)CpuInf + ProcssOffs), sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION));
	}
}


// Print interrupts info of target -
void PrintInterruptInfo(PVOID IntInf, ULONG64 EntrySize, char* ProcessorsNum) {
	ULONG unslong = 0;
	ULONG IntOffs = 0;
	SYSTEM_INTERRUPT_INFORMATION Sysint;

	printf("Interrupts Data on target:\n");
	memcpy(&Sysint, IntInf, sizeof(SYSTEM_INTERRUPT_INFORMATION));
	for (ULONG i = 0; i < (ULONG)*ProcessorsNum; i++) {
		printf("Processor number %lu -\n", i + 1);
		GetBufferValue(Sysint.Reserved1, &unslong, sizeof(unslong));  printf("  Total amount context switches while in interrupts ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Sysint.Reserved1 + 4), &unslong, sizeof(unslong));  printf("  DPC count ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Sysint.Reserved1 + 8), &unslong, sizeof(unslong));  printf("  DPC rate ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Sysint.Reserved1 + 12), &unslong, sizeof(unslong));  printf("  Time increment of interrupts ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Sysint.Reserved1 + 16), &unslong, sizeof(unslong));  printf("  Total amount of DPC bypasses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Sysint.Reserved1 + 20), &unslong, sizeof(unslong)); printf("  Total amount of APC bypasses ULONG -> %lu\n", unslong);
		IntOffs += sizeof(SYSTEM_INTERRUPT_INFORMATION);
		memcpy(&Sysint, (PVOID)((ULONG64)IntInf + IntOffs), sizeof(SYSTEM_INTERRUPT_INFORMATION));
	}
}


// Print exceptions info of target -
void PrintExceptionInfo(PVOID ExcInf, ULONG64 EntrySize) {
	ULONG unslong = 0;
	SYSTEM_EXCEPTION_INFORMATION* ExInfo = (SYSTEM_EXCEPTION_INFORMATION*)ExcInf;

	printf("Exceptions Data on target:\n");
	GetBufferValue(ExInfo->Reserved1, &unslong, sizeof(unslong));  printf("  Total amount of allignment fixups ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)ExInfo->Reserved1 + 4), &unslong, sizeof(unslong));  printf("  Total amount of exception dispatches ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)ExInfo->Reserved1 + 8), &unslong, sizeof(unslong));  printf("  Total amount of floating emulations ULONG -> %lu\n", unslong);
	GetBufferValue((PVOID)((ULONG64)ExInfo->Reserved1 + 12), &unslong, sizeof(unslong));  printf("  Total amount of byteword emulations ULONG -> %lu\n", unslong);
}


// Print system lookaside info of target -
void PrintLookasideInfo(PVOID LookasdInfo, ULONG64 EntrySize) {
	ULONG LookasdOffs = 0;
	ULONG unslong = 0;
	USHORT unsshort = 0;
	SYSTEM_LOOKASIDE_INFORMATION Currlook;
	memcpy(&Currlook, (PVOID)((ULONG64)LookasdInfo + LookasdOffs), sizeof(SYSTEM_LOOKASIDE_INFORMATION));
	PVOID Currlist = &Currlook.Reserved1;

	printf("Information on system lookaside data on target:\n");

	for (int l = 0; l < EntrySize / sizeof(SYSTEM_LOOKASIDE_INFORMATION); l++) {
		printf("List in index %lu -\n", l);
		GetBufferValue(Currlist, &unsshort, sizeof(unsshort));  printf("  Current depth USHORT -> %hu\n", unsshort);
		GetBufferValue((PVOID)((ULONG64)Currlist + 2), &unsshort, sizeof(unsshort));  printf("  Maximum depth USHORT -> %hu\n", unsshort);
		GetBufferValue((PVOID)((ULONG64)Currlist + 4), &unslong, sizeof(unslong));  printf("  Total amount of allocate operations ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Currlist + 8), &unslong, sizeof(unslong));  printf("  Total amount of allocate misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Currlist + 12), &unslong, sizeof(unslong));  printf("  Total amount of free operations ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Currlist + 16), &unslong, sizeof(unslong));  printf("  Total amount of misses ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Currlist + 20), &unslong, sizeof(unslong));  printf("  List type ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Currlist + 24), &unslong, sizeof(unslong));  printf("  List tag ULONG -> %lu\n", unslong);
		GetBufferValue((PVOID)((ULONG64)Currlist + 28), &unslong, sizeof(unslong));  printf("  List size ULONG -> %lu\n", unslong);

		LookasdOffs += sizeof(SYSTEM_LOOKASIDE_INFORMATION);
		memcpy(&Currlook, (PVOID)((ULONG64)LookasdInfo + LookasdOffs), sizeof(SYSTEM_LOOKASIDE_INFORMATION));
		Currlist = &Currlook.Reserved1;
	}
}


// Print system code integrity info of target -
void PrintCodeIntgrInfo(PVOID CodeintgrInfo, ULONG64 EntrySize) {
	ULONG unslong = 0;
	SYSTEM_CODEINTEGRITY_INFORMATION* CodeInf = (SYSTEM_CODEINTEGRITY_INFORMATION*)CodeintgrInfo;
	printf("Information on system code integrity on target:\n");
	printf("  Length of output ULONG -> %lu\n", CodeInf->Length);
	printf("  Code integrity options ULONG -> %lu ", CodeInf->CodeIntegrityOptions);
	switch (CodeInf->CodeIntegrityOptions) {
	case 1: printf("(CODEINTEGRITY_OPTION_ENABLED)\n"); break;
	case 2: printf("(CODEINTEGRITY_OPTION_TESTSIGN)\n"); break;
	case 4: printf("(CODEINTEGRITY_OPTION_UMCI_ENABLED)\n"); break;
	case 8: printf("(CODEINTEGRITY_OPTION_UMCI_AUDITMODE_ENABLED)\n"); break;
	case 16: printf("(CODEINTEGRITY_OPTION_UMCI_EXCLUSIONPATHS_ENABLED)\n"); break;
	case 0x80: printf("(CODEINTEGRITY_OPTION_DEBUGMODE_ENABLED)\n"); break;
	case 0x200: printf("(CODEINTEGRITY_OPTION_FLIGHTING_ENABLED)\n"); break;
	case 0x400: printf("(CODEINTEGRITY_OPTION_HVCI_KMCI_ENABLED)\n"); break;
	case 0x800: printf("(CODEINTEGRITY_OPTION_HVCI_KMCI_AUDITMODE_ENABLED)\n"); break;
	case 0x1000: printf("(CODEINTEGRITY_OPTION_HVCI_KMCI_STRICTMODE_ENABLED)\n"); break;
	default: printf("(CODEINTEGRITY_OPTION_HVCI_IUM_ENABLED)\n"); break;
	}
}


// General function for printing info -
void PrintSystemInformation(PVOID Response, char c, ULONG64 status, DWORD n, ULONG64 Size, char* ProcessorsNum) {
	printf("\n");
	printf("=====System Data Number %lu START=====", n);
	printf("\n");
	if (status == ROOTKSTATUS_SUCCESS) {
		switch (c) {
		case 'r':
			PrintRegistryData(Response, Size); break;

		case 'b':
			PrintBasicSystemInfo(Response, Size, ProcessorsNum); break;

		case 'p':
			PrintSystemPerformanceInfo(Response, FALSE, Size); break;

		case 't':
			PrintTimeOfDayInfo(Response, Size); break;

		case 'c':
			PrintWorkingProcessesInfo(Response, Size); break;

		case 'P':
			PrintCpuPerformanceInfo(Response, Size, ProcessorsNum); break;

		case 'i':
			PrintInterruptInfo(Response, Size, ProcessorsNum); break;

		case 'e':
			PrintExceptionInfo(Response, Size); break;
		}
	}
	printf("=====System Data Number %lu END=====\n\n", n);
}


SYSTEM_INFORMATION_CLASS ReturnSystemInfo(char InfoType) {
	switch (InfoType) {
	case 'r':
		return SystemRegistryQuotaInformation;

	case 'b':
		return SystemBasicInformation;

	case 'p':
		return SystemPerformanceInformation;

	case 't':
		return SystemTimeOfDayInformation;

	case 'c':
		return SystemProcessInformation;

	case 'P':
		return SystemProcessorPerformanceInformation;

	case 'i':
		return SystemInterruptInformation;

	case 'e':
		return SystemExceptionInformation;

	case 'L':
		return SystemLookasideInformation;

	case 'I':
		return SystemCodeIntegrityInformation;

	default:
		return (SYSTEM_INFORMATION_CLASS)9999;
	}
}