#include "parameter_handling.h"


BOOL ValidateParameters(int argc, char* argv[]) {
	char DriverExtension[5] = { 0 };
	struct stat CheckExists = { 0 };
	if (argc < 2) {
		printf("[-] USAGE: ShayMapper.exe [path to driver]\n");
		return FALSE;
	}
	if (strlen(argv[1]) < 5) {
		printf("[-] USAGE: ShayMapper.exe [path to driver]\n");
		return FALSE;
	}
	RtlCopyMemory(DriverExtension, (PVOID)((ULONG64)argv[1] + strlen(argv[1]) - 4), 5);
	if (strcmp(DriverExtension, ".sys") != 0) {
		printf("[-] USAGE: ShayMapper.exe [path to driver]\n");
		return FALSE;
	}
	if (stat(argv[1], &CheckExists) != 0) {
		printf("[-] USAGE: ShayMapper.exe [EXISTING path to driver]\n");
		return FALSE;
	}
	printf("[+] Mapping driver from path %s\n", argv[1]);
	return TRUE;
}