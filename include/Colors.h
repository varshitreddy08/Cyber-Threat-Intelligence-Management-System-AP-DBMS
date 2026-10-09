#pragma once
// Terminal color codes for Windows console output
#include <string>

namespace Color {
    const std::string RESET   = "\033[0m";
    const std::string RED     = "\033[31m";
    const std::string GREEN   = "\033[32m";
    const std::string YELLOW  = "\033[33m";
    const std::string BLUE    = "\033[34m";
    const std::string MAGENTA = "\033[35m";
    const std::string CYAN    = "\033[36m";
    const std::string WHITE   = "\033[37m";
    const std::string BOLD    = "\033[1m";

    inline std::string severity_color(const std::string& sev) {
        if (sev == "Critical") return RED + BOLD;
        if (sev == "High")     return RED;
        if (sev == "Medium")   return YELLOW;
        return GREEN;
    }
}
