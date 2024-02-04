#include "utils.h"


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


int GetNumFromString(char Str[]) {
    int sum = 0;
    for (int i = 0; i < strlen(Str); i++) {
        if (!(Str[i] >= '0' && Str[i] <= '9')) {
            return -1;
        }
        sum = sum * 10 + (Str[i] - 0x30);
    }
    return sum;
}


void ResetString(char Str[]) {
    char StringClnChr = '\0';
    for (int i = 0; i < strlen(Str) + 1; i++) {
        StringClnChr = Str[i];
        Str[i] = '\0';  // placeholder for initialization of char[]
        if (StringClnChr == '\0') {
            break;
        }
    }
}


void WideResetString(WCHAR Str[]) {
    WCHAR StringClnChr = L'\0';
    for (int i = 0; i < lstrlenW(Str) + 1; i++) {
        StringClnChr = Str[i];
        Str[i] = L'\0';  // placeholder for initialization of char[]
        if (StringClnChr == L'\0') {
            break;
        }
    }
}


BOOL ValidateFileReqPath(char FilePath[], char Type) {
    const char* InvalidPathChrs = "|/:*?\"<>";
    BOOL LastBacks = FALSE;
    if (strlen(FilePath) == 0) {
        return FALSE;
    }
    for (int invi = 0; invi < strlen(InvalidPathChrs); invi++) {
        if (CountOccurrences(FilePath, InvalidPathChrs[invi]) != 0) {
            return FALSE;
        }
    }
    if (FilePath[strlen(FilePath) - 1] == '.') {
        return FALSE;  // File name cannot end in a '.'
    }

    if (Type == 'g') {
        if (CountOccurrences(FilePath, '\\') != 0) {
            return FALSE;
        }
    }
    else {
        if (strlen(FilePath) == 1 || FilePath[0] != '\\') {
            return FALSE;  // Guided by the syntax of KM functions to receive path from handle
        }
        if (FilePath[strlen(FilePath) - 1] == '\\') {
            return FALSE;  // File name cannot end in a '\'
        }
        LastBacks = TRUE;

        for (int filepi = 1; filepi < strlen(FilePath); filepi++) {
            if (FilePath[filepi] == '\\') {
                if (LastBacks) {
                    return FALSE;
                }
                LastBacks = TRUE;
            }
            else {
                if (LastBacks) {
                    LastBacks = FALSE;
                }
            }
        }
    }
    return TRUE;
}


char ReturnInput(const char* PrintfStr) {
    char inp;

    printf(PrintfStr);
    std::cin >> inp;
    fflush(stdin);
    return inp;  // return the input given by the user
}


DWORD CountOccurrences(const char* SearchStr, char SearchLetter) {
	DWORD Count = 0;
	for (int i = 0; i < strlen(SearchStr); i++) {
		if (SearchStr[i] == SearchLetter) {
			Count++;
		}
	}
	return Count;
}


BOOL CheckForValidIp(char* Address) {
	DWORD CurrChunkValue = 0;
	if (CountOccurrences(Address, '.') != 3) {
		printf("\nIPV4 address chunks are not seperated correctly with dots, check format ..\n");
		return FALSE;
	}

	for (int i = 0; i < strlen(Address); i++) {
		if (Address[i] != '.') {
			if (isdigit(Address[i]) == 0 && Address[i]) {
				printf("\nOne or more chunk consists of values other than numeric values, check format ..\n");
				return FALSE;
			}
			CurrChunkValue *= 10;
			CurrChunkValue += (Address[i] - 0x30);
		}
		else {
			if (!(CurrChunkValue > 0 && CurrChunkValue <= 255)) {
				printf("\nOne or more chunk consists of a value outside the 0-255 range for each chunk, check format ..\n");
				return FALSE;
			}
			CurrChunkValue = 0;
		}
	}
	return TRUE;
}


DWORD CompareIpAddresses(char* LocalHost, char* RemoteAddr) {
    DWORD Score = 0;
    DWORD LocalInd = 0;
    DWORD RemoteInd = 0;
    DWORD MaskValue = 0x80;
    DWORD CurrMask = 0x80;
    DWORD MatchingFields = 0;
    DWORD LocalNumeric = 0;
    DWORD RemoteNumeric = 0;

    while (MatchingFields != 4) {
        while (LocalHost[LocalInd] != '.' && LocalHost[LocalInd] != '\0') {
            LocalNumeric *= 10;
            LocalNumeric += (LocalHost[LocalInd] - 0x30);
            LocalInd++;
        }

        while (RemoteAddr[RemoteInd] != '.' && RemoteAddr[RemoteInd] != '\0') {
            RemoteNumeric *= 10;
            RemoteNumeric += (RemoteAddr[RemoteInd] - 0x30);
            RemoteInd++;
        }

        while (CurrMask != 0) {
            if ((RemoteNumeric & CurrMask) == (LocalNumeric & CurrMask)) {
                Score++;
            }
            else {
                return Score;
            }
            CurrMask /= 2;
        }
        RemoteInd++;
        LocalInd++;
        MatchingFields++;
        LocalNumeric = 0;
        RemoteNumeric = 0;
        CurrMask = MaskValue;
    }
    return Score;  // If got here - 32, probably not possible, exactly like current IP address
}


BOOL MatchIpAddresses(char* AttackerAddress, char* TargetAddress) {
    char LocalHostName[80];
    char NewLine = '\n';
    char NullTerm = '\0';
    char* CurrAttackIp = NULL;

    struct hostent* LocalIpsList = NULL;
    DWORD CompareScore = 0;
    DWORD CurrentScore = 0;
    WSADATA SockData = { 0 };
    if (WSAStartup(MAKEWORD(2, 2), &SockData) != 0) {
        return FALSE;
    }


    // Get the hostname of the local machine to get ip addresses -
    if (gethostname(LocalHostName, sizeof(LocalHostName)) == SOCKET_ERROR) {
        printf("%d when getting local host name!", WSAGetLastError());
        WSACleanup();
        return FALSE;
    }
    LocalIpsList = gethostbyname(LocalHostName);
    if (LocalIpsList == 0) {
        WSACleanup();
        return FALSE;
    }


    // Find the address pair with the most similar bits in the address -
    for (int i = 0; LocalIpsList->h_addr_list[i] != 0; ++i) {
        struct in_addr addr;
        memcpy(&addr, LocalIpsList->h_addr_list[i], sizeof(struct in_addr));
        CurrAttackIp = inet_ntoa(addr);
        CurrentScore = CompareIpAddresses(CurrAttackIp, TargetAddress);
        if (CurrentScore > CompareScore) {
            CompareScore = CurrentScore;
            RtlZeroMemory(AttackerAddress, MAX_IPV4_SIZE);
            memcpy(AttackerAddress, CurrAttackIp, strlen(CurrAttackIp) + 1);
            AttackerAddress[strlen(CurrAttackIp) + 1] = '\0';
        }
    }
    WSACleanup();
    return TRUE;
}