#include "minifilter.h"
#include "MinifilterGlobals.h"


NTSTATUS FilterGeneral::RegisterDriverAsMinifilter(PDRIVER_OBJECT DriverObject) {
    const FLT_OPERATION_REGISTRATION MinifilterCallbacks[] = {
    { IRP_MJ_CREATE,
      0,
      FilterPreoperations::PreOperationCreate,
      NULL,
      NULL },
    { IRP_MJ_READ,
      0,
      FilterPreoperations::PreOperationRead,
      NULL,
      NULL },
    { IRP_MJ_WRITE,
      0,
      FilterPreoperations::PreOperationWrite,
      NULL,
      NULL },
    { IRP_MJ_QUERY_INFORMATION,
      0,
      FilterPreoperations::PreOperationQueryInformation,
      NULL,
      NULL }, 
    { IRP_MJ_DIRECTORY_CONTROL,
      0,
      FilterPreoperations::PreOperationDirectoryControl,
      NULL,
      NULL },
    /*
    { IRP_MJ_FILE_SYSTEM_CONTROL,
      0,
      FilterPreoperations::PreOperationFileSystemControl,
      NULL,
      NULL },
    { IRP_MJ_DEVICE_CONTROL,
      0,
      FilterPreoperations::PreOperationDeviceControl,
      NULL,
      NULL },
    */
    {IRP_MJ_OPERATION_END}};


    // Initialize the registration list for the minifilter:
    MinifilterRegistration = {
    sizeof(FLT_REGISTRATION),                        //  Size
    FLT_REGISTRATION_VERSION,                        //  Version
    0,                                               //  Flags
    NULL,                                            //  Context Registration.
    MinifilterCallbacks,                             //  Operation callbacks
    FilterGeneral::MinifilterUnload,                 //  FilterUnload
    FilterGeneral::MinifilterSetupCallback,          //  InstanceSetup
    FilterGeneral::MinifilterQueryTeardownCallback,  //  InstanceQueryTeardown
    NULL,                                            //  InstanceTeardownStart
    NULL,                                            //  InstanceTeardownComplete
    NULL,                                            //  GenerateFileName
    NULL,                                            //  GenerateDestinationFileName
    NULL                                             //  NormalizeNameComponent
    };
	return FltRegisterFilter(DriverObject, &MinifilterRegistration, &MinifilterObject);
}


NTSTATUS FilterGeneral::StartFilteringWithMinifilter() {
    NTSTATUS Status = FltStartFiltering(MinifilterObject);
    if (!NT_SUCCESS(Status)) {
        DbgPrintEx(0, 0, "KMDFdriver minifilter - Cannot start filtering, status = 0x%x\n", Status);
        FilterGeneral::MinifilterUnload(NULL);
    }
    DbgPrintEx(0, 0, "KMDFdriver minifilter - Started filtering files and directories\n");
    return Status;
}


NTSTATUS FLTAPI FilterGeneral::MinifilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags) {
    UNREFERENCED_PARAMETER(Flags);
    if (MinifilterObject != NULL) {
        FltUnregisterFilter(MinifilterObject);
    }
    DbgPrintEx(0, 0, "KMDFdriver minifilter - Unregistered minifilter\n");
    return STATUS_SUCCESS;  // Might add more post operation cleaning here
}


NTSTATUS FLTAPI FilterGeneral::MinifilterSetupCallback(
    _In_ PCFLT_RELATED_OBJECTS  FltObjects,
    _In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
    _In_ DEVICE_TYPE  VolumeDeviceType,
    _In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType){
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    UNREFERENCED_PARAMETER(VolumeFilesystemType);
    DbgPrintEx(0, 0, "KMDFdriver minifilter - SetupCallback() called\n");
    return STATUS_SUCCESS;
}


NTSTATUS FLTAPI FilterGeneral::MinifilterQueryTeardownCallback(
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags){
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    DbgPrintEx(0, 0, "KMDFdriver minifilter - QueryTeardownCallback() called\n");
    return STATUS_SUCCESS;
}




FLT_PREOP_CALLBACK_STATUS FLTAPI FilterPreoperations::PreOperationCreate(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    DbgPrint("KMDFdriver minifilter - Create preoperation log: %wZ\n", &Data->Iopb->TargetFileObject->FileName);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS FLTAPI FilterPreoperations::PreOperationWrite(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS FLTAPI FilterPreoperations::PreOperationRead(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS FLTAPI FilterPreoperations::PreOperationQueryInformation(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}


FLT_PREOP_CALLBACK_STATUS FLTAPI FilterPreoperations::PreOperationDirectoryControl(
    _Inout_ PFLT_CALLBACK_DATA Data,
    _In_ PCFLT_RELATED_OBJECTS FltObjects,
    _Flt_CompletionContext_Outptr_ PVOID* CompletionContext
) {
    UNREFERENCED_PARAMETER(Data);
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(CompletionContext);
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}