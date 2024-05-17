#include <iostream>
#include <windows.h>
#include "Process.hpp"
#include <TlHelp32.h>
#include <psapi.h>

std::error_code getLastEC()
{
  return std::error_code{ (int)GetLastError(), std::system_category() };
}

std::string getLastErrorMsg()
{
  return getLastEC().message();
}

std::error_code getLastErrno()
{
  return std::error_code{ errno, std::system_category() };
}

PIDtoPathMap getProcessList()
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (INVALID_HANDLE_VALUE == hProcessSnap)
    {
        std::cerr << "Unable to create process list snapshot!" << std::endl;
        return {};
    }

    pe32.dwSize = sizeof(MODULEENTRY32);

    // Retrieve information about the first process,
    // and exit if unsuccessful
    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap); // clean the snapshot object
        std::cerr << "Failed to gather information on system processes!" << std::endl;
        return {};
    }

    PIDtoPathMap Ret;

    do
    {
        const uint32_t pid = pe32.th32ProcessID;
        char Path[MAX_PATH + 1];
        HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
        if (hProc == NULL)
        {
            auto Err = getLastEC();
            if (Err && Err.value() != ERROR_ACCESS_DENIED)
            {
                std::cerr << "Warning: unable to open process " << pid << ": " << Err.message() << std::endl;
            }
            continue;
        }
        uint32_t size = MAX_PATH;
        if (!GetModuleFileNameExA(hProc, NULL, Path, MAX_PATH))
        {
            std::cerr << "Warning: unable to retrieve the full path of the process for PID " << pid << ": " << getLastErrorMsg() << std::endl;
            continue;
        }
        CloseHandle(hProc);

        Ret.insert(std::make_pair(std::string{Path}, ProcessInfo{std::string{Path}, pe32.th32ProcessID}));
    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);

    return Ret;
}

uint32_t getPIDByPath(PIDtoPathMap const &fileMap, const char *Path)
{
    auto It = fileMap.find(Path);
    if (It == fileMap.end())
    {
        std::cerr << "Unable to find a running process mapped to " << Path << std::endl;
        return -1;
    }

    return It->second.PID;
}

std::string getProcessPathFromPID(PIDtoPathMap const &fileMap, uint32_t Pid)
{
    for (auto const &P : fileMap)
    {
        if (P.second.PID == Pid)
        {
            return P.second.FullPath;
        }
    }

    return std::string{};
}

// int main(){
//     PIDtoPathMap temp = getProcessList();

//     for(auto &P : temp){
//         std::cout << P.second.PID << " " << P.second.FullPath << std::endl;
//     }

//     return 0;
// }