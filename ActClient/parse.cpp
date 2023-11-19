#include "parse.h"


void GetBufferValue(PVOID Src, PVOID Dst, SIZE_T Size) {
	memcpy(Dst, Src, Size);
}


/*
====================================================================================================
SYSTEM INFORMATION FUNCTIONS (VALIDATE TYPE STRING + GET INFO TYPE + PRINTS + CASTING THE POINTERS):
====================================================================================================
*/


// Check for valid info type string - 
static BOOL ValidateInfoTypeString(const char* InfoType) {
	if (strlen(InfoType) > 5 || strlen(InfoType) == 0) {
		return FALSE;
	}

	std::string cppString("rbptcPiemCIL");
	for (int i = 0; InfoType[i] != '\0'; i++) {
		if (cppString.find(InfoType[i]) == std::string::npos) {
			return FALSE;
		}
	}
	return TRUE;
}


// Return an array with InfoTypes as an array - 
SYSTEM_INFORMATION_CLASS ReturnSystemInfo(char InfoType) {
	switch (InfoType) {
	case 'r':
		return SystemRegistryQuotaInformation;

	case 'b':
		return SystemBasicInformation;

	case 'p':
		return SystemPerformanceInformation;

	case 't':
		return SystemTimeOfDayInformation;

	case 'c':
		return SystemProcessInformation;

	case 'P':
		return SystemProcessorPerformanceInformation;

	case 'i':
		return SystemInterruptInformation;

	case 'e':
		return SystemExceptionInformation;

	case 'm':
		return SystemModuleInformation;

	case 'L':
		return SystemLookasideInformation;

	case 'I':
		return SystemCodeIntegrityInformation;

	case 'C':
		return SystemPolicyInformation;

	default:
		return (SYSTEM_INFORMATION_CLASS)9999;
	}
}