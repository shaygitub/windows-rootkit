#pragma once
#include <iostream>
#include "requests.h"
#include "utils.h"
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>


int ReqAct(NETWORK_INFO Sender, NETWORK_INFO Server);