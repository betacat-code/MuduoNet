
#include "net_services/EventLoopThread.h"
EventLoopThread::EventLoopThread(const ThreadInitCallback &cb,
                                 const std::string &name)
    : loop_(nullptr)
    , exiting_(false)
    , thread_(std::bind(&EventLoopThread::threadFunc, this), name) // 新线程绑定此函数
    , mutex_()
    , cond_()
    , callback_(cb) // 传入的线程初始化回调函数，用户自定义的
{

}

EventLoopThread::~EventLoopThread()
{
    exiting_ = true;
    if (loop_ != nullptr)
    {
        loop_->quit();
        thread_.join();
    }
}

EventLoop* EventLoopThread::startLoop()
{
    thread_.start();
    EventLoop *loop = nullptr;
    {
        // 等待新线程执行threadFunc完毕，所以使用cond_.wait
        std::unique_lock<std::mutex> lock(mutex_);
        while (loop_ == nullptr)
        {
            cond_.wait(lock);
        }
        loop = loop_;
    }
    return loop;
}

void EventLoopThread::threadFunc()
{
    EventLoop loop;
    if(callback_)
    {
        callback_(&loop);
    }
    
    {
        std::unique_lock<std::mutex> lock(mutex_);
        loop_ = &loop; // 等到生成EventLoop对象之后才唤醒
        cond_.notify_one();
    }
    //loop生成了
    loop.loop();
    //loop是一个事件循环，如果往下执行说明停止了事件循环，需要关闭eventLoop
    std::unique_lock<std::mutex> lock(mutex_);
    loop_=nullptr;
}