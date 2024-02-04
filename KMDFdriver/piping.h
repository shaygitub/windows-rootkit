#pragma once
#include "hooking.h"

void ShrootUnload(PDRIVER_OBJECT DriverObject);
NTSTATUS ShowDominanceADD(PCWSTR DomFileName);  // SHOW DOMINANCE, RAAA
BOOL ShouldRenewDriverADD(PCWSTR DomFileName, BOOL Silent);  // Returns TRUE if a newer driver has dominance over current driver, else FALSE
NTSTATUS OpenPipe(HANDLE* PipeHandle, POBJECT_ATTRIBUTES PipeNameAttr, PIO_STATUS_BLOCK PipeStatusBlock, BOOL Silent);
void ClosePipe(HANDLE* PipeHandle);
NTSTATUS WritePipe(HANDLE* PipeHandle, PIO_STATUS_BLOCK PipeStatusBlock, PVOID InputBuffer, SIZE_T BufferSize);
NTSTATUS ReadPipe(HANDLE* PipeHandle, PIO_STATUS_BLOCK PipeStatusBlock, PVOID OutputBuffer, SIZE_T BufferSize);
void PipeClient();