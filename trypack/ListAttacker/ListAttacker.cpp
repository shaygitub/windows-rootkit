#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <WinSock2.h>
#include <iostream>
#include <Windows.h>
#include <fileapi.h>
#pragma comment(lib, "Ws2_32.lib")


std::wstring ExePath() {
    TCHAR buffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, buffer, MAX_PATH);
    std::wstring::size_type pos = std::wstring(buffer).find_last_of(L"\\/");
    return std::wstring(buffer).substr(0, pos);
}


int main()
{
    char LocalHostName[80];
    char Tilda = '~';
    char AttackerPrefix[] = "const char* AttackAddresses = \"";
    const char* AfterLastAddress = "\";";
    char* CurrAttackIp = NULL;
    WCHAR FilePath[MAX_PATH] = { 0 };
    WCHAR FileName[29] = L"AttackerFile\\attackerips.txt";
    struct hostent* LocalIpsList = NULL;
    HANDLE Attacker = INVALID_HANDLE_VALUE;
    DWORD AttackWrite = 0;
    DWORD BacksCount = 0;
    int PathIndex = 0;
    int MaxPathIndex = 0;
    std::wstring CurrPath = ExePath();
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


    // Get the path of the package solution for comfortable creation -
    for (PathIndex = lstrlenW(CurrPath.c_str()); BacksCount != 3; PathIndex--) {
        if (CurrPath[PathIndex] == '\\') {
            BacksCount++;
        }
    }
    MaxPathIndex = PathIndex + 1;
    for (PathIndex = 0; PathIndex <= MaxPathIndex; PathIndex++) {
        FilePath[PathIndex] = CurrPath[PathIndex];
    }

    for (int i = 0; i < lstrlenW(FileName); i++, PathIndex++) {
        FilePath[PathIndex] = FileName[i];
    }
    FilePath[PathIndex] = '\0';


    // Put data in the attackerips.txt file -
    Attacker = CreateFileW(FilePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (Attacker == INVALID_HANDLE_VALUE) {
        WSACleanup();
        printf("create - %d\n", GetLastError());
        return FALSE;
    }

    if (!WriteFile(Attacker, AttackerPrefix, strlen(AttackerPrefix), &AttackWrite, NULL) || AttackWrite != strlen(AttackerPrefix)) {
        WSACleanup();
        CloseHandle(Attacker);
        printf("write prefix - %d\n", GetLastError());
        return FALSE;
    }

    for (int i = 0; LocalIpsList->h_addr_list[i] != 0; ++i) {
        struct in_addr addr;
        memcpy(&addr, LocalIpsList->h_addr_list[i], sizeof(struct in_addr));
        CurrAttackIp = inet_ntoa(addr);
        if (!WriteFile(Attacker, CurrAttackIp, strlen(CurrAttackIp), &AttackWrite, NULL) || AttackWrite != strlen(CurrAttackIp)) {
            WSACleanup();
            CloseHandle(Attacker);
            printf("write ip %s - %d\n", CurrAttackIp, GetLastError());
            return FALSE;
        }

        if (LocalIpsList->h_addr_list[i + 1] == 0) {
            if (!WriteFile(Attacker, AfterLastAddress, strlen(AfterLastAddress), &AttackWrite, NULL) || AttackWrite != strlen(AfterLastAddress)) {
                WSACleanup();
                CloseHandle(Attacker);
                printf("write last ip after address - %d\n", GetLastError());
                return FALSE;
            }
        }
        else {
            if (!WriteFile(Attacker, &Tilda, 1, &AttackWrite, NULL) || AttackWrite != 1) {
                WSACleanup();
                CloseHandle(Attacker);
                printf("write ip %s tilda after address - %d\n", CurrAttackIp, GetLastError());
                return FALSE;
            }
        }
    }

    CloseHandle(Attacker);
    WSACleanup();
    return TRUE;
}