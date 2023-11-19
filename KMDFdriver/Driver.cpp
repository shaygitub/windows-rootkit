#include "hooking.h"


typedef struct _DRIVER_ENTRY_PARAMS{
    UINT_PTR MappedAddress{};
    SIZE_T MappedSize{};
}DRIVER_ENTRY_PARAMS, *PDRIVER_ENTRY_PARAMS;


extern "C" NTSTATUS DriverEntry(DRIVER_OBJECT * DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(DriverObject);
    UNREFERENCED_PARAMETER(RegistryPath);
    if (!roothook::KernelFunctionHook(&roothook::HookHandler, "\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtQueryCompositionSurfaceStatistics")) {
        return STATUS_UNSUCCESSFUL;
    }
    
    NTSTATUS status = STATUS_SUCCESS;
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