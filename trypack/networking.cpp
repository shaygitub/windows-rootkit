#include "networking.h"
#include "utils.h"


DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr) {
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


BOOL MatchIpAddresses(char* TargetAddress, char* AttackerAddress, const char* AttackerIps) {
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
    while (AddrIndex < strlen(AttackerIps)){
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