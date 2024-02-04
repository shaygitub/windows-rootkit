#pragma once
#include <fltKernel.h>
#include "helpers.h"


namespace FilterGeneral {
	NTSTATUS RegisterDriverAsMinifilter(PDRIVER_OBJECT DriverObject);
	NTSTATUS StartFilteringWithMinifilter();
	NTSTATUS FLTAPI MinifilterUnload(_In_ FLT_FILTER_UNLOAD_FLAGS Flags);
	NTSTATUS FLTAPI MinifilterSetupCallback(
		_In_ PCFLT_RELATED_OBJECTS  FltObjects,
		_In_ FLT_INSTANCE_SETUP_FLAGS  Flags,
		_In_ DEVICE_TYPE  VolumeDeviceType,
		_In_ FLT_FILESYSTEM_TYPE  VolumeFilesystemType);
	NTSTATUS FLTAPI MinifilterQueryTeardownCallback(
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_In_ FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags
	);
}

namespace FilterPreoperations {
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationCreate(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationWrite(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationRead(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationQueryInformation(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationDirectoryControl(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	/*
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationFileSystemControl(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	FLT_PREOP_CALLBACK_STATUS FLTAPI PreOperationDeviceControl(
		_Inout_ PFLT_CALLBACK_DATA Data,
		_In_ PCFLT_RELATED_OBJECTS FltObjects,
		_Flt_CompletionContext_Outptr_ PVOID* CompletionContext
	);
	*/  // Not important for now
}

//namespace FilterPostoperations {
//
//}