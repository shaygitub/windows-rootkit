// Copyright (c) 2015-2017, Satoshi Tanda. All rights reserved.
// Use of this source code is governed by a MIT-style license that can be
// found in the LICENSE file.

#include "stdafx.h"

// C/C++ standard headers
// Other external headers
// Windows headers
// Original headers

namespace stdexp = std::experimental;

////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//

////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

////////////////////////////////////////////////////////////////////////////////
//
// types
//

////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

namespace {

void Usage();

bool AppMain(_In_ int Argc, _In_ TCHAR* const Argv[]);

bool IsServiceInstalled(_In_ LPCTSTR ServiceName);

bool LoadDriver(_In_ LPCTSTR ServiceName, _In_ LPCTSTR DriverFile,
                _In_ bool IsFilterDriver);

SC_HANDLE LoadStandardDriver(_In_ LPCTSTR ServiceName, _In_ LPCTSTR DriverFile);

SC_HANDLE LoadFilterDriver(_In_ LPCTSTR ServiceName, _In_ LPCTSTR DriverFile);

bool UnloadDriver(_In_ LPCTSTR ServiceName);

void PrintErrorMessage(_In_ const char* Message);

std::string GetErrorMessage(_In_ DWORD ErrorCode);

}  // namespace

////////////////////////////////////////////////////////////////////////////////
//
// variables
//

////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

int _tmain(int argc, _TCHAR* argv[]) {
  int result = EXIT_FAILURE;
  try {
    if (AppMain(argc, argv)) {
      result = EXIT_SUCCESS;
    }
  } catch (std::exception& e) {
    std::cout << e.what() << std::endl;
  } catch (...) {
    std::cout << "Unknown Exception." << std::endl;
  }
  return result;
}

namespace {

void Usage() {
  std::cout << "usage:\n"
            << "    >DrvLoader.exe [--filter | -F] <DriverFile>\n" << std::endl;
}

bool AppMain(_In_ int Argc, _In_ TCHAR* const Argv[]) {
  if (Argc == 1) {
    Usage();
    return false;
  }

  auto isFilterDriver = false;
  auto index = 1;
  if (Argc == 3) {
    const std::basic_string<TCHAR> param = Argv[index++];
    if (param == _T("--filter") || param == _T("-F") || param == _T("/F")) {
      isFilterDriver = true;
    } else {
      Usage();
      return false;
    }
  }
  const auto driverName = Argv[index];

  TCHAR fullPath[MAX_PATH];
  if (!::PathSearchAndQualify(driverName, fullPath, _countof(fullPath))) {
    PrintErrorMessage("PathSearchAndQualify failed");
    return false;
  }

  if (!::PathFileExists(fullPath)) {
    PrintErrorMessage("PathFileExists failed");
    return false;
  }

  // Create a service name
  TCHAR serviceName[MAX_PATH];
  if (!SUCCEEDED(
          ::StringCchCopy(serviceName, _countof(serviceName), fullPath))) {
    PrintErrorMessage("StringCchCopy failed");
    return false;
  }

  ::PathRemoveExtension(serviceName);
  ::PathStripPath(serviceName);

  if (IsServiceInstalled(serviceName)) {
    // Uninstall the service when it has already been installed
    if (!UnloadDriver(serviceName)) {
      PrintErrorMessage("UnloadDriver failed");
      return false;
    }
    std::cout << "Unloaded the driver successfully" << std::endl;
  } else {
    // Install the service when it has not been installed yet
    if (!LoadDriver(serviceName, fullPath, isFilterDriver)) {
      if (::GetLastError() == ERROR_INVALID_PARAMETER) {
        std::cout << "the driver was executed and unloaded." << std::endl;
        return true;
      }
      PrintErrorMessage("LoadDriver failed");
      return false;
    }
    std::cout << "Loaded the driver successfully" << std::endl;
  }
  return true;
}

// Returns true when a specified service has been installed.
bool IsServiceInstalled(_In_ LPCTSTR ServiceName) {
  const auto scmHandle = stdexp::make_unique_resource(
      ::OpenSCManager(nullptr, nullptr, GENERIC_READ), &::CloseServiceHandle);
  return (FALSE != ::CloseServiceHandle(::OpenService(
                       scmHandle.get(), ServiceName, GENERIC_READ)));
}

// Loads a driver file as a file system filter driver.
bool LoadDriver(_In_ LPCTSTR ServiceName, _In_ LPCTSTR DriverFile,
                _In_ bool IsFilterDriver) {
  const auto loader = (IsFilterDriver) ? LoadFilterDriver : LoadStandardDriver;
  const auto serviceHandle = stdexp::make_unique_resource(
      loader(ServiceName, DriverFile), &::CloseServiceHandle);
  if (!serviceHandle) {
    PrintErrorMessage("LoadStandardDriver or LoadFilterDriver failed");
    return false;
  }

  // Start the service
  SERVICE_STATUS status = {};
  if (::StartService(serviceHandle.get(), 0, nullptr)) {
    while (::QueryServiceStatus(serviceHandle.get(), &status)) {
      if (status.dwCurrentState != SERVICE_START_PENDING) {
        break;
      }

      ::Sleep(500);
    }
  } else {
    PrintErrorMessage("StartService failed");
  }

  if (status.dwCurrentState != SERVICE_RUNNING) {
    ::DeleteService(serviceHandle.get());
    return false;
  }
  return true;
}

// Loads a driver file as a standard driver.
SC_HANDLE LoadStandardDriver(_In_ LPCTSTR ServiceName,
                             _In_ LPCTSTR DriverFile) {
  const auto scmHandle = stdexp::make_unique_resource(
      ::OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE),
      &::CloseServiceHandle);
  if (!scmHandle) {
    return false;
  }

  return ::CreateService(scmHandle.get(), ServiceName, ServiceName,
                         SERVICE_ALL_ACCESS, SERVICE_KERNEL_DRIVER,
                         SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DriverFile,
                         nullptr, nullptr, nullptr, nullptr, nullptr);
}

// Loads a driver file as a mini-filter driver.
SC_HANDLE LoadFilterDriver(_In_ LPCTSTR ServiceName, _In_ LPCTSTR DriverFile) {
  // See MSDN 'Load Order Groups and Altitudes for Minifilter Drivers' for
  // details of altitudes.
  // https://msdn.microsoft.com/en-us/library/windows/hardware/ff549689%28v=vs.85%29.aspx
  static const TCHAR ALTITUDE[] = _T("370000");

  // Create registry values for a file system driver
  TCHAR fsRegistry[260];
  if (!SUCCEEDED(::StringCchPrintf(
          fsRegistry, _countof(fsRegistry),
          _T("SYSTEM\\CurrentControlSet\\Services\\%s\\Instances"),
          ServiceName))) {
    return false;
  }

  HKEY key = nullptr;
  if (ERROR_SUCCESS != ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, fsRegistry, 0,
                                        nullptr, 0, KEY_ALL_ACCESS, nullptr,
                                        &key, nullptr)) {
    return false;
  }

  const auto valueSize = (::wcslen(ServiceName) + 1) * 2;
  const auto scopedRegCloseKey =
      stdexp::make_scope_exit([key] { ::RegCloseKey(key); });
  if (ERROR_SUCCESS !=
      ::RegSetValueEx(key, _T("DefaultInstance"), 0, REG_SZ,
                      reinterpret_cast<const BYTE*>(ServiceName), valueSize)) {
    return false;
  }

  ::StringCchCat(fsRegistry, _countof(fsRegistry), _T("\\"));
  if (!SUCCEEDED(
          ::StringCchCat(fsRegistry, _countof(fsRegistry), ServiceName))) {
    return false;
  }

  HKEY keySub = nullptr;
  if (ERROR_SUCCESS != ::RegCreateKeyEx(HKEY_LOCAL_MACHINE, fsRegistry, 0,
                                        nullptr, 0, KEY_ALL_ACCESS, nullptr,
                                        &keySub, nullptr)) {
    return false;
  }
  const auto scopedRegCloseKey2 =
      stdexp::make_scope_exit([keySub] { ::RegCloseKey(keySub); });

  if (ERROR_SUCCESS != ::RegSetValueEx(keySub, _T("Altitude"), 0, REG_SZ,
                                       reinterpret_cast<const BYTE*>(ALTITUDE),
                                       sizeof(ALTITUDE))) {
    return false;
  }

  DWORD regValue = 0;
  if (ERROR_SUCCESS != ::RegSetValueEx(keySub, _T("Flags"), 0, REG_DWORD,
                                       reinterpret_cast<const BYTE*>(&regValue),
                                       sizeof(regValue))) {
    return false;
  }

  const auto scmHandle = stdexp::make_unique_resource(
      ::OpenSCManager(nullptr, nullptr, SC_MANAGER_CREATE_SERVICE),
      &::CloseServiceHandle);
  if (!scmHandle) {
    return false;
  }

  return ::CreateService(scmHandle.get(), ServiceName, ServiceName,
                         SERVICE_ALL_ACCESS, SERVICE_FILE_SYSTEM_DRIVER,
                         SERVICE_DEMAND_START, SERVICE_ERROR_NORMAL, DriverFile,
                         _T("FSFilter Activity Monitor"), nullptr, _T("FltMgr"),
                         nullptr, nullptr);
}

// Unloads a driver and deletes its service.
bool UnloadDriver(_In_ LPCTSTR ServiceName) {
  const auto scmHandle = stdexp::make_unique_resource(
      ::OpenSCManager(nullptr, nullptr, SC_MANAGER_CONNECT),
      &::CloseServiceHandle);
  if (!scmHandle) {
    return false;
  }

  const auto serviceHandle = stdexp::make_unique_resource(
      ::OpenService(scmHandle.get(), ServiceName,
                    DELETE | SERVICE_STOP | SERVICE_QUERY_STATUS),
      &::CloseServiceHandle);
  if (!serviceHandle) {
    return false;
  }

  ::DeleteService(serviceHandle.get());

  // Stop the service
  SERVICE_STATUS status = {};
  if (::ControlService(serviceHandle.get(), SERVICE_CONTROL_STOP, &status)) {
    while (::QueryServiceStatus(serviceHandle.get(), &status)) {
      if (status.dwCurrentState != SERVICE_START_PENDING) break;

      Sleep(500);
    }
  }

  TCHAR fsRegistry[260];
  if (SUCCEEDED(StringCchPrintf(fsRegistry, _countof(fsRegistry),
                                _T("SYSTEM\\CurrentControlSet\\Services\\%s\\"),
                                ServiceName))) {
    ::SHDeleteKey(HKEY_LOCAL_MACHINE, fsRegistry);
  }

  return (status.dwCurrentState == SERVICE_STOPPED);
}

void PrintErrorMessage(_In_ const char* Message) {
  const auto errorCode = ::GetLastError();
  const auto errorMessage = GetErrorMessage(errorCode);
  ::fprintf_s(stderr, "%s : %lu(0x%08x) : %s\n", Message, errorCode, errorCode,
              errorMessage.c_str());
}

std::string GetErrorMessage(_In_ DWORD ErrorCode) {
  char* message = nullptr;
  if (!::FormatMessageA(
          FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM, nullptr,
          ErrorCode, LANG_USER_DEFAULT, reinterpret_cast<LPSTR>(&message), 0,
          nullptr)) {
    return "";
  }
  const auto scopedLocalFree =
      stdexp::make_scope_exit([message] { ::LocalFree(message); });

  const auto length = ::strlen(message);
  if (!length) {
    return "";
  }

  if (message[length - 2] == '\r') {
    message[length - 2] = '\0';
  }
  return message;
}

}  // namespace
