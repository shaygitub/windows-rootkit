#pragma once
#include "requests.h"


namespace service {
	NTSTATUS HideDriverService(DRIVER_OBJECT* DriverObject, PUNICODE_STRING DriverName);
	NTSTATUS HideService(PUNICODE_STRING ServiceName);
	NTSTATUS HideProcess(USHORT ProcessId, PUNICODE_STRING ProcessName);
}