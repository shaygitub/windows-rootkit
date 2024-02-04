#include "internet.h"

/*
=======================================================
FUNCTIONS FOR REQUESTING SPECIFIC REQUESTS FROM MEDIUM:
=======================================================
*/


BOOL IsQuickTerm(PASS_DATA result) {
    return result.err && (result.value == 10054 || result.value == 10060 || result.value == 10053 || result.value == 0);
}


PASS_DATA SendData(SOCKET SendTo, PVOID SrcData, int Size, BOOL Silent, int Flags) {
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
    SndRes.err = IsQuickTerm(SndRes);
    return SndRes;
}


PASS_DATA RecvData(SOCKET GetFrom, int Size, PVOID ToBuf, BOOL Silent, int Flags) {
    PASS_DATA RecRes;

    // Receive data -
    int result = recv(GetFrom, (char*)ToBuf, Size, Flags);
    if (result > 0) {
        // Correct message / size mismatch -

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
        // Nothing was sent -

        RecRes.err = TRUE;
        RecRes.value = result;
        if (!Silent) {
            printf("Socket connection to sending socket was closed\n");
        }
    }

    else {
        // Error -

        RecRes.err = TRUE;
        RecRes.value = WSAGetLastError();
        if (!Silent) {
            std::cerr << "Error receiving data from sending socket: " << RecRes.value << "\n";
        }
    }
    RecRes.err = IsQuickTerm(RecRes);
    return RecRes;
}


void CleanNetStack(SOCKET sockfrom) {
    char LastChr = NULL;
    PASS_DATA result;
    ULONG LastBytes = 0;
    BOOL Err = FALSE;

    int res = ioctlsocket(sockfrom, FIONREAD, &LastBytes);  // Get the amount of the unused data in the network stack in bytes
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


NETWORK_INFO InitNetInfo(sockaddr_in AddrInfo, USHORT Port, const char* IP, SOCKET Sock) {
    // ASSUMES: AddrInfo is initialized correctly (port number, ipv4, value of ip address)
    NETWORK_INFO Info;
    Info.AddrInfo = AddrInfo;
    Info.IP = IP;
    Info.Port = Port;
    Info.AsoSock = Sock;
    return Info;
}


void SetNetStructs(const char* SrvIP, const char* SndIP, USHORT SrvPort, USHORT SndPort, NETWORK_INFO* NetArr) {

    // Current information -
    sockaddr_in SndAddr;
    SndAddr.sin_family = AF_INET;
    SndAddr.sin_port = SndPort;
    inet_pton(AF_INET, SndIP, &(SndAddr.sin_addr));
    NetArr[0] = InitNetInfo(SndAddr, SndPort, SndIP, NULL);


    // Medium information -
    sockaddr_in Addr;
    Addr.sin_family = AF_INET;
    Addr.sin_port = SrvPort;
    inet_pton(AF_INET, SrvIP, &(Addr.sin_addr));
    NetArr[1] = InitNetInfo(Addr, SrvPort, SrvIP, NULL);
}


// Pass the module name used for operation (string = const char *, passes the VA) -
BOOL PassString(SOCKET tosock, const char* String) {
    ULONG StringSize = (ULONG)strlen(String) + 1;
    char MallocConfirm = 0;

    PASS_DATA result = SendData(tosock, &StringSize, sizeof(StringSize), FALSE, 0);
    if (result.err || result.value != sizeof(StringSize)) {
        return FALSE;
    }

    result = RecvData(tosock, sizeof(MallocConfirm), &MallocConfirm, FALSE, 0);
    if (result.err || result.value != sizeof(MallocConfirm) || MallocConfirm == 0) {
        return FALSE;
    }

    result = SendData(tosock, (PVOID)String, StringSize, FALSE, 0);
    if (result.err || result.value != StringSize) {
        return FALSE;
    }

    return TRUE;
}


// Passing the main structure to the medium -
BOOL PassArgs(ROOTKIT_MEMORY* Rootinst, SOCKET tosock, BOOL Retrieve) {
    PASS_DATA result = SendData(tosock, Rootinst, sizeof(ROOTKIT_MEMORY), FALSE, 0);
    if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
        return FALSE;
    }

    if (Retrieve) {
        result = RecvData(tosock, sizeof(ROOTKIT_MEMORY), Rootinst, FALSE, 0);
        if (result.err || result.value != sizeof(ROOTKIT_MEMORY)) {
            return FALSE;
        }
    }
    return TRUE;
}