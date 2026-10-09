#pragma once

#include <string>
#include <mutex>
#include <iostream>

namespace netguard {

enum class LogLevel {
    DEBUG,
    INFO,
    WARNING,
    ERROR
};

class Logger {
public:
    static Logger& instance();

    void set_level(LogLevel level);
    void log(LogLevel level, const std::string& message);

    void info(const std::string& msg) { log(LogLevel::INFO, msg); }
    void warn(const std::string& msg) { log(LogLevel::WARNING, msg); }
    void error(const std::string& msg) { log(LogLevel::ERROR, msg); }
    void debug(const std::string& msg) { log(LogLevel::DEBUG, msg); }

private:
    Logger() = default;
    LogLevel current_level_{LogLevel::INFO};
    std::mutex mutex_;
};

} // namespace netguard
