#include "utils.h"


int general::CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString) {
    int WideNameLen = MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, NULL, 0);
    MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, ConvertedString, WideNameLen);
    return WideNameLen;
}


int general::WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString) {
    int MultiByteLen = WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, ConvertedString, MultiByteLen, NULL, NULL);
    return MultiByteLen;
}


std::wstring general::GetCurrentPathWide(std::wstring AddName) {
    WCHAR PathBuffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, PathBuffer, MAX_PATH);
    std::wstring::size_type PathEndPos = std::wstring(PathBuffer).find_last_of(L"\\/");
    std::wstring CurrentPath = std::wstring(PathBuffer).substr(0, PathEndPos);
    if (AddName.c_str() != NULL) {
        return CurrentPath + AddName;
    }
    return CurrentPath;
}


void general::GetCurrentPathRegular(char Path[], std::wstring AddName) {
    std::wstring WideCurrentPath = GetCurrentPathWide(AddName);
    general::WcharpToCharp(Path, WideCurrentPath.c_str());
}


int general::CountOccurrences(const char* SearchStr, char SearchLetter) {
    DWORD Count = 0;
    for (int i = 0; i < strlen(SearchStr); i++) {
        if (SearchStr[i] == SearchLetter) {
            Count++;
        }
    }
    return Count;
}


void general::GetServiceName(char* Path, char* Buffer) {
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


void general::ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size) {
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


DWORD general::ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size) {
    char Command[500] = { 0 };
    general::ReplaceValues(BaseCommand, RepArr, Command, Size);
    if (system(Command) == -1) {
        return GetLastError();
    }
    return 0;
}


void general::GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension) {
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


int general::GetPidByName(const char* Name) {
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


int general::CheckLetterInArr(char Chr, const char* Arr) {
    for (int i = 0; i < strlen(Arr); i++) {
        if (Arr[i] == Chr) {
            return i;
        }
    }
    return -1;
}


BOOL general::PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount) {
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
    SystemReturn = system(ActualCommand);
    if (SystemReturn == -1) {
        free(ActualCommand);
        return FALSE;
    }
    free(ActualCommand);
    return TRUE;
}


DWORD specific::MemoryToFile(LPCWSTR FileName, BYTE MemoryData[], SIZE_T MemorySize) {
    DWORD BytesWritten = 0;
    HANDLE VulnHandle = INVALID_HANDLE_VALUE;
    VulnHandle = CreateFileW(FileName, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (VulnHandle == INVALID_HANDLE_VALUE) {
        return GetLastError();
    }
    if (!WriteFile(VulnHandle, MemoryData, MemorySize, &BytesWritten, NULL) || BytesWritten != MemorySize) {
        CloseHandle(VulnHandle);
        return GetLastError();
    }
    CloseHandle(VulnHandle);
    return 0;
}


PVOID specific::GetKernelModuleAddress(const char* ModuleName) {
    PVOID ModulesInfo = NULL;
    ULONG ModulesLength = 0;
    NTSTATUS Status = ERROR_SUCCESS;
    nt::PRTL_PROCESS_MODULES ActualModules = NULL;
    char CurrentName[MAX_PATH] = { 0 };


    // Get a right-sized buffer for the modules info:
    Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, ModulesInfo, ModulesLength, &ModulesLength);
    while (Status == nt::STATUS_INFO_LENGTH_MISMATCH) {
        if (ModulesInfo != NULL) {
            VirtualFree(ModulesInfo, 0, MEM_RELEASE);
        }
        ModulesInfo = VirtualAlloc(NULL, ModulesLength, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        Status = NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)nt::SystemModuleInformation, ModulesInfo, ModulesLength, &ModulesLength);
    }
    if (!NT_SUCCESS(Status) || ModulesInfo == NULL) {
        if (ModulesInfo != NULL) {
            VirtualFree(ModulesInfo, 0, MEM_RELEASE);
        }
        return NULL;
    }


    // Iterate through system modules (includes kernel somewhere):
    ActualModules = (nt::PRTL_PROCESS_MODULES)ModulesInfo;
    for (int modulei = 0; modulei < ActualModules->NumberOfModules; modulei++) {
        RtlZeroMemory(CurrentName, MAX_PATH);
        RtlCopyMemory(CurrentName, (PVOID)((ULONG64)ActualModules->Modules[modulei].FullPathName + ActualModules->Modules[modulei].OffsetToFileName), strlen((const char*)ActualModules->Modules[modulei].FullPathName) - ActualModules->Modules[modulei].OffsetToFileName);
        if (strcmp(CurrentName, ModuleName) == 0) {
            VirtualFree(ModulesInfo, 0, MEM_RELEASE);
            return ActualModules->Modules[modulei].ImageBase;
        }
    }
    VirtualFree(ModulesInfo, 0, MEM_RELEASE);
    return NULL;  // Did not find the system module
}


BOOL specific::CompareBetweenData(const BYTE DataToCheck[], const BYTE CheckAgainst[], const char* SearchMask) {
    for (int maski = 0; SearchMask[maski] != '\0'; maski++) {
        if (SearchMask[maski] == 'x' && DataToCheck[maski] != CheckAgainst[maski]) {
            return FALSE;  // x = compare in this offset of both data streams
        }
    }
    return TRUE;
}


PVOID specific::FindPattern(PVOID StartingAddress, ULONG SearchLength, BYTE CheckAgainst[], const char* SearchMask) {
    for (ULONG searchi = 0; searchi < SearchLength - strlen(SearchMask); searchi++) {
        if (specific::CompareBetweenData((BYTE*)StartingAddress + searchi, CheckAgainst, SearchMask)) {
            return (PVOID)((ULONG64)StartingAddress + searchi);
        }
    }
    return NULL;
}


PVOID specific::FindSectionOfKernelModule(const char* SectionName, PVOID HeadersPointer, ULONG* SectionSize) {
    PIMAGE_NT_HEADERS ModuleHeaders = (PIMAGE_NT_HEADERS)((ULONG64)HeadersPointer + ((PIMAGE_DOS_HEADER)HeadersPointer)->e_lfanew);
    PIMAGE_SECTION_HEADER ModuleSections = IMAGE_FIRST_SECTION(ModuleHeaders);
    PIMAGE_SECTION_HEADER CurrentSection = NULL;
    for (ULONG sectioni = 0; sectioni < ModuleHeaders->FileHeader.NumberOfSections; sectioni++) {
        CurrentSection = &ModuleSections[sectioni];
        if (strcmp(SectionName, (char*)CurrentSection->Name) == 0) {
            if (CurrentSection->VirtualAddress == 0) {
                return NULL;  // Offset from start of file, first 0x10000 are headers
            }
            if (SectionSize != NULL) {
                *SectionSize = CurrentSection->Misc.VirtualSize;
            }
            return (PVOID)((ULONG64)HeadersPointer + CurrentSection->VirtualAddress);
        }
    }
    return NULL;
}


PVOID specific::GetKernelModuleExport(HANDLE* DeviceHandle, PVOID KernelBaseAddress, const char* ExportName) {
    
}


BOOL specific::HandleResourceLite(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID FunctionResource, BOOL ShouldWait, BOOL IsAcquire) {
    PVOID FunctionAddress = NULL;
    if (FunctionResource == NULL) {
        return FALSE;
    }
    if (IsAcquire) {
        FunctionAddress = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExAcquireResourceExclusiveLite");
        if (FunctionAddress == NULL) {
            printf("[-] Failed to get the address of ExAcquireResourceExclusiveLite\n");
            return FALSE;
        }
    }
    else {
        FunctionAddress = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "ExReleaseResourceLite");
        if (FunctionAddress == NULL) {
            printf("[-] Failed to get the address of ExReleaseResourceLite\n");
            return FALSE;
        }
    }
    return specific::CallKernelFunction(DeviceHandle, NULL, FunctionAddress, FunctionResource);
}