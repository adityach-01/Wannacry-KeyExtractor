#ifndef PROCESS_H
#define PROCESS_H

#include <iostream>
#include <map>
#include <string>
#include <cstdint>
#include <system_error>
#include <vector>

struct ProcessInfo{
    std::string FullPath;
    uint32_t PID;
};

typedef std::map<std::string, ProcessInfo> PIDtoPathMap;
PIDtoPathMap getProcessList();
uint32_t getPIDByPath(PIDtoPathMap const& PIDs, const char* Path);
std::string getProcessPathFromPID(PIDtoPathMap const& Procs, uint32_t Pid);

std::error_code getLastEC();
std::error_code getLastErrno();
std::string getLastErrorMsg();

#endif