#ifndef LOG_FILE_H
#define LOG_FILE_H

#include "log_services/FileUtil.h"
#include <mutex>
#include <memory>

class LogFile
{
public:
    LogFile(const std::string& basename,
            off_t rollSize,
            int flushInterval = 3,
            int checkEveryN = 1024);
    ~LogFile()=default;

    void append(const char* data, int len);
    bool rollFile();
    void flush();
private:
    std::string getLogFileName(const std::string& basename, time_t* now);
    void appendInLock(const char* data, int len);

    const std::string basename_;
    const off_t rollSize_;//滚动日志的大小阈值
    const int flushInterval_;//日志刷新间隔
    const int checkEveryN_;//每写入多少条日志进行一次滚动检查

    int counts_;//已写入的日志条
    
    std::unique_ptr<std::mutex> mutex_;
    time_t startOfPeriod_;
    time_t lastRoll_;
    time_t lastFlush_;
    std::unique_ptr<FileUtil> file_;

    const static int kRollPerSeconds_ = 60*60*24;

};

#endif