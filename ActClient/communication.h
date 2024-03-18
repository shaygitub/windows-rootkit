#pragma once
#include <iostream>
#include "requests.h"
#include "utils.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>


int ClientOperation(NETWORK_INFO Sender, NETWORK_INFO Server);