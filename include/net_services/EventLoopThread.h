#ifndef EVENT_LOOP_THREAD_H
#define EVENT_LOOP_THREAD_H

#include <functional>
#include <mutex>
#include <condition_variable>
#include "base_components/noncopyable.h"
#include "base_components/Thread.h"
#include "net_services/EventLoop.h"

class EventLoopThread
{
public:
    using ThreadInitCallback = std::function<void(EventLoop*)>;
    
    EventLoopThread(const ThreadInitCallback &cb = ThreadInitCallback(),
                    const std::string &name = std::string());
    ~EventLoopThread();

    EventLoop *startLoop(); // 开启线程池

private:
    void threadFunc();

    // EventLoopThread::threadFunc 会创建 EventLoop
    EventLoop *loop_;   
    bool exiting_;
    Thread thread_;
    std::mutex mutex_;
    std::condition_variable cond_;
    ThreadInitCallback callback_;
};

#endif