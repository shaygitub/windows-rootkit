#include "helpers.h"


std::uint32_t GetPID(std::string PrcName) {
	PROCESSENTRY32 PrcEntry;
	const UniqueHndl snapshot_handle(CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL));  // take snapshot of all current processes
	if (snapshot_handle.get() == INVALID_HANDLE_VALUE) {
		return NULL; // invalid handle
	}
	PrcEntry.dwSize = sizeof(PROCESSENTRY32);  // set size of function process entry (after validating the given handle)
	while (Process32Next(snapshot_handle.get(), &PrcEntry) == TRUE) {
		std::wstring wideExeFile(PrcEntry.szExeFile);
		std::string narrowExeFile(wideExeFile.begin(), wideExeFile.end());

		if (strcmp(PrcName.c_str(), narrowExeFile.c_str()) == 0) {
			return PrcEntry.th32ProcessID;  // return the PID of the required process from the process snapshot
		}
	}
	return NULL;  // if something did not work correctly
}


// Check for valid info type string - 
BOOL ValidateInfoTypeString(const char* InfoType) {
	if (strlen(InfoType) > 5 || strlen(InfoType) == 0) {
		return FALSE;
	}

	std::string cppString("rbptcPieIL");
	for (int i = 0; InfoType[i] != '\0'; i++) {
		if (cppString.find(InfoType[i]) == std::string::npos) {
			return FALSE;
		}
	}
	return TRUE;
}