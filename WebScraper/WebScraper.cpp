#include <iostream>
#include <Windows.h>


BOOL IsValidIp(char* IpAddress) {
    USHORT CurrentChunk = 0;

    if (IpAddress == NULL) {
        return FALSE;
    }
    if (strlen(IpAddress) > 15) {
        return FALSE;  // Bigger than length of maximum IP (xxx.xxx.xxx.xxx)
    }
    for (int IpIndex = 0; IpIndex < strlen(IpAddress); IpIndex++) {
        if (!(IpAddress[IpIndex] >= '0' && IpAddress[IpIndex] <= '9')) {
            if (IpAddress[IpIndex] != '.') {
                return FALSE;
            }
            if (IpIndex == 0) {
                return FALSE;  // First character is a dot
            }
            if (IpAddress[IpIndex - 1] == '.') {
                return FALSE;  // 2 consecutive dots
            }
            if (CurrentChunk > 255) {
                return FALSE;
            }
            CurrentChunk = 0;
        }
        else {
            CurrentChunk *= 10;
            CurrentChunk += (IpAddress[IpIndex] - 0x30);
        }
    }
    return TRUE;
}


int MakeDirectoryNotNullTerm(char* FullDirectoryPath) {
    std::string DirectoryPath(FullDirectoryPath);
    char CreateDirPath[1024] = { 0 };
    char DeleteExistCommand[1024] = { 0 };
    char CreateCommand[1024] = { 0 };
    RtlCopyMemory(CreateDirPath, FullDirectoryPath, DirectoryPath.find("\n"));
    CreateDirPath[DirectoryPath.find("\n")] = '\0';
    strcat_s(DeleteExistCommand, "rmdir /s /q ");
    strcat_s(DeleteExistCommand, CreateDirPath);
    strcat_s(CreateCommand, "mkdir ");
    strcat_s(CreateCommand, CreateDirPath);
    if (system(DeleteExistCommand) == -1 ||
        system(CreateCommand) == -1) {
        return 0;
    }
    printf("[+] Created directory %s\n", CreateDirPath);
    return (int)DirectoryPath.find("\n") + 2;  // Skip the '\n' character to get to the next line
}


int DownloadFileFromHost(char* FilePath, char* FileHostIp, char* FileHostingPort) {
    std::string DownloadFilePaths(FilePath);
    char RelativeFileHostPath[1024] = { 0 };
    char AbsoluteDownloadPath[1024] = { 0 };
    char DeleteExistCommand[1024] = { 0 };
    char CurlCommand[1024] = { 0 };
    RtlCopyMemory(AbsoluteDownloadPath, FilePath, DownloadFilePaths.find("?"));
    AbsoluteDownloadPath[DownloadFilePaths.find("?")] = '\0';
    RtlCopyMemory(RelativeFileHostPath,
    (char*)((ULONG64)FilePath + DownloadFilePaths.find("?") + 1),
        DownloadFilePaths.find("\n") - DownloadFilePaths.find("?") - 1);
    RelativeFileHostPath[DownloadFilePaths.find("\n") - DownloadFilePaths.find("?") - 1] = '\0';
    strcat_s(DeleteExistCommand, "del /s /q ");
    strcat_s(DeleteExistCommand, AbsoluteDownloadPath);
    strcat_s(CurlCommand, "curl http://");
    strcat_s(CurlCommand, FileHostIp);
    strcat_s(CurlCommand, ":");
    strcat_s(CurlCommand, FileHostingPort);
    strcat_s(CurlCommand, "/");
    strcat_s(CurlCommand, RelativeFileHostPath);
    strcat_s(CurlCommand, " --output ");
    strcat_s(CurlCommand, AbsoluteDownloadPath);
    if (system(DeleteExistCommand) == -1 ||
        system(CurlCommand) == -1) {
        return 0;
    }
    printf("[+] Downloaded file into %s\n", AbsoluteDownloadPath);
    return (int)DownloadFilePaths.find("\n") + 1;  // Skip the '\n' character to get to the next line
}


BOOL DownloadFilesFromCatalog(char* FileHostIp, char* CatalogFilePath) {
    char FileHostingPort[] = "8080";
    char* CatalogFileData = NULL;
    HANDLE CatalogFileHandle = INVALID_HANDLE_VALUE;
    DWORD CatalogFileSize = 0;
    DWORD CatalogFileRead = 0;
    int CurrentAddOffset = 0;


    // Read data from catalog file:
    CatalogFileHandle = CreateFileA(CatalogFilePath, GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (CatalogFileHandle == INVALID_HANDLE_VALUE) {
        return FALSE;
    }
    CatalogFileSize = GetFileSize(CatalogFileHandle, NULL);
    CatalogFileData = (char*)malloc(CatalogFileSize);
    if (CatalogFileData == NULL) {
        CloseHandle(CatalogFileHandle);
        return FALSE;
    }
    if (!ReadFile(CatalogFileHandle, CatalogFileData, CatalogFileSize,
        &CatalogFileRead, NULL) || CatalogFileRead != CatalogFileSize) {
        free(CatalogFileData);
        CloseHandle(CatalogFileHandle);
        return FALSE;
    }


    // Process lines letter by letter:
    for (DWORD CatalogIndex = 0; CatalogIndex < CatalogFileSize;) {
        if (CatalogFileData[CatalogIndex] == '*') {
            CurrentAddOffset = MakeDirectoryNotNullTerm((char*)((ULONG64)CatalogFileData + CatalogIndex + 1));
            if (CurrentAddOffset == 0){
                free(CatalogFileData);
                CloseHandle(CatalogFileHandle);
                return FALSE;
            }
            CatalogIndex += CurrentAddOffset;
        }
        else {
            CurrentAddOffset = DownloadFileFromHost((char*)((ULONG64)CatalogFileData + CatalogIndex), FileHostIp, FileHostingPort);
            if (CurrentAddOffset == 0) {
                free(CatalogFileData);
                CloseHandle(CatalogFileHandle);
                return FALSE;
            }
            CatalogIndex += CurrentAddOffset;
        }
        printf("Current catalog index: %d\n", CatalogIndex);
    }
    return TRUE;
}


int main(int argc, char* argv[]) {
    struct stat CheckExists = { 0 };
    if (argc != 3) {
        printf("[-] Usage - WebScraper.exe catalog_file.txt filehost_ip\n");
        return 0;
    }
    if (stat(argv[1], &CheckExists) != 0) {
        printf("[-] Usage: WebScraper.exe EXISTING_CATALOG_FILE.txt filehost_ip\n");
        return 0;
    }
    if (!IsValidIp(argv[2])) {
        printf("[-] Usage: WebScraper.exe catalog_file.txt VALID_FILEHOST_IP\n");
        return 0;
    }
    return (int)DownloadFilesFromCatalog(argv[2], argv[1]);
}