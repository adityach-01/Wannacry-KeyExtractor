#include "Wcry.hpp"
#include "FileUtils.hpp"
#include <iostream>
#include <windows.h>


static uint32_t getWcryPIDByDir(PIDtoPathMap const& PIDs)
{
  // First check: Wannacry registers its current directory into registry base.
  // Find every exe files, and drop taskdl.exe and taskse.exe. If more than one
  // exe remains, grep for WNcry@2ol7 (the decryption key of the DLL).  Then,
  // search for this process in memory!

  // From the sample I have...
  const char* subkey = "Software\\wanacrypt0r";
  const char* value = "wd";

  HKEY hKey;
  if (RegOpenKeyEx(HKEY_LOCAL_MACHINE, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_64KEY, &hKey) != ERROR_SUCCESS) {
	  if (RegOpenKeyEx(HKEY_CURRENT_USER, subkey, 0, KEY_QUERY_VALUE | KEY_WOW64_32KEY, &hKey) != ERROR_SUCCESS) {
	  std::cerr << "unable to load registry key HKEY_(LOCAL_MACHINE|CURRENT_USER)\\" << subkey << ": " << getLastErrorMsg() << std::endl;
	  return -1;
	  }
  }

  DWORD curDirSize;
  if (RegQueryValueEx(hKey, value, 0, NULL, NULL, &curDirSize) != ERROR_SUCCESS) {
    std::cerr << "unable to load registry value " << subkey << "\\" << value << ": " << getLastErrorMsg() << std::endl;
    return -1;
  }

  char* RootDir = (char*)malloc(curDirSize);
  if (!RootDir) {
    std::cerr << "unable to allocate data for the current directory!" << std::endl;
    return -1;
  }
  if (RegQueryValueEx(hKey, value, 0, NULL, (uint8_t*)RootDir, &curDirSize) != ERROR_SUCCESS) {
    std::cerr << "unable to load registry value " << subkey << "\\" << value << ": " << getLastErrorMsg() << std::endl;
    return -1;
  }
  RegCloseKey(hKey);

  std::cerr << "Current directory is '" << RootDir << "'" << std::endl;

  std::string pattern = RootDir;
  pattern += "\\*.exe";

  WIN32_FIND_DATA fd;
  HANDLE hFind = FindFirstFile(pattern.c_str(), &fd);
  if (hFind == INVALID_HANDLE_VALUE) {
    std::cerr << "Enumerating exe using '" << pattern << "' failed: " << getLastErrorMsg() << std::endl;
    return -1;
  }

  std::vector<std::string> files;
  do {
    if ((_stricmp(fd.cFileName, "taskdl.exe") == 0) ||
        (_stricmp(fd.cFileName, "taskse.exe") == 0) ||
		(_stricmp(fd.cFileName, "@WanaDecryptor@.exe") == 0)) {
      continue;
    }
    std::string FullPath = RootDir;
    FullPath += "\\";
    FullPath += fd.cFileName;
    files.push_back(FullPath);
  } while (FindNextFile(hFind, &fd));

  if (files.size() == 1) {
    return getPIDByPath(PIDs, files[0].c_str());
  }

  for (std::string const& path : files) {
    if (fileHasString(path.c_str(), "WNcry@2ol7")) {
      std::cout << "Find potential decrypting binary at '" << path.c_str() << "..." << std::endl;
      auto PID = getPIDByPath(PIDs, path.c_str());
      if (PID != -1) {
        return PID;
      }
    }
  }

  return -1;
}

uint32_t getWcryPIDByList(PIDtoPathMap const& PIDs)
{
  for (auto const& It : PIDs) {
    const char* Name = strrchr(It.second.FullPath.c_str(), '\\');
    if (!Name) continue;

    Name += 1;
    if (_stricmp(Name, "wcry.exe") == 0 || _stricmp(Name, "wncry.exe") == 0) {
      return It.second.PID;
    }
  }
  return -1;
}

uint32_t getWannaCryProcessPID(PIDtoPathMap const& PIDs)
{
  uint32_t Ret;

  Ret = getWcryPIDByDir(PIDs);
  if (Ret != -1) {
    return Ret;
  }

  // If this fails, we get back to a hardcoded list of known names, and look
  // for them in memory!
  return getWcryPIDByList(PIDs);
}

