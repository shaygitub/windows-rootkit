#pragma once
#include "helpers.h"

NTSTATUS GetModuleBaseRK(ROOTKIT_MEMORY* RootkInst);  // get the base address of a process in memory (i.e notepad.exe)
NTSTATUS WriteToMemoryRK(ROOTKIT_MEMORY* RootkInst);  // write into memory (UM-UM, supports user supplied buffers from ActClient)
NTSTATUS ReadFromMemoryRK(ROOTKIT_MEMORY* RootkInst);  // read from memory (UM-MainMedium)
NTSTATUS PrintDbgMsgRK(ROOTKIT_MEMORY* RootkInst); // print a debug string to a kernel debugger (i.e windbg)
NTSTATUS RetrieveSystemInformationRK(ROOTKIT_MEMORY* RootkInst);  // retrieve system information by request
NTSTATUS AllocSpecificMemoryRK(ROOTKIT_MEMORY* RootkInst);  // allocate specified memory in a memory range in a process virtual address space