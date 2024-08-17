#ifndef ASYNC_LOGGING_H
#define ASYNC_LOGGING_H

#include "base_components/Thread.h"
#include "log_services/FixedBuffer.h"
#include "log_services/LogStream.h"
#include "log_services/LogFile.h"


#include <vector>
#include <memory>
#include <mutex>
#include <condition_variable>

class AsyncLogging
{
public:
public:
    AsyncLogging(const std::string& basename,
                 off_t rollSize,
                 int flushInterval = 3);
    ~AsyncLogging();
    // 前端调用 append 写入日志
    void append(const char* logling, int len);
    void start();
    void stop();

private:
    using Buffer = FixedBuffer<kLargeBuffer>;
    using BufferVector = std::vector<std::unique_ptr<Buffer>>;
    using BufferPtr = std::unique_ptr<Buffer>;

    void threadFunc();

    const int flushInterval_;
    std::atomic<bool> running_;
    const std::string basename_;
    const off_t rollSize_;
    Thread thread_;
    std::mutex mutex_;
    std::condition_variable cond_;

    BufferPtr currentBuffer_;
    BufferPtr nextBuffer_;
    BufferVector buffers_;
};



#endif