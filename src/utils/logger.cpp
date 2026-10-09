#include "netguard/utils/logger.hpp"
#include <chrono>
#include <iomanip>

namespace netguard {

Logger& Logger::instance() {
    static Logger logger;
    return logger;
}

void Logger::set_level(LogLevel level) {
    std::lock_guard lock(mutex_);
    current_level_ = level;
}

void Logger::log(LogLevel level, const std::string& message) {
    std::lock_guard lock(mutex_);
    if (level < current_level_) {
        return;
    }

    auto now = std::chrono::system_clock::now();
    auto in_time_t = std::chrono::system_clock::to_time_t(now);

    std::string lvl_str;
    switch (level) {
        case LogLevel::DEBUG:   lvl_str = "[DEBUG]"; break;
        case LogLevel::INFO:    lvl_str = "[INFO] "; break;
        case LogLevel::WARNING: lvl_str = "[WARN] "; break;
        case LogLevel::ERROR:   lvl_str = "[ERROR]"; break;
    }

    std::cout << std::put_time(std::localtime(&in_time_t), "%Y-%m-%d %H:%M:%S")
              << " " << lvl_str << " " << message << std::endl;
}

} // namespace netguard
