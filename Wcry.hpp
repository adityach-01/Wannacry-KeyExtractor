#ifndef WCRY_H
#define WCRY_H

#include "Process.hpp"

#include <cstdint>
#include <string>
#include <map>

#include <vector>
#include <system_error>

uint32_t getWannaCryProcessPID(PIDtoPathMap const& fileMap);

#endif