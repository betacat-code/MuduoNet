#include "base_components/Thread.h"
#include <sys/syscall.h>
#include <unistd.h>
int Thread::ThreadNums_=0;

Thread::Thread(ThreadFunc func, const std::string &name) :
    started_(false), // 还未开始
    joined_(false),  // 还未设置等待线程
    tid_(0),         // 初始 tid 设置为0
    func_(std::move(func)), // EventLoopThread::threadFunc()
    name_(name)     // 默认姓名是空字符串

{
    // 设置线程索引编号和姓名
    setDefaultName();
}

Thread::~Thread()
{
    // 现场感启动时并且未设置等待线程时才可调用
    if (started_ && !joined_)
    {
        // 设置线程分离(守护线程，不需要等待线程结束，不会产生孤儿线程)
        thread_->detach();
    }
}

void Thread::start()
{
    started_ = true;
    thread_ = std::shared_ptr<std::thread>(new std::thread([&](){
        // 获取线程tid
        tid_ = syscall(SYS_gettid);
        // 开启一个新线程专门执行该线程函数
        func_();
    }));
}

void Thread::join()
{
    joined_ = true;
    // 等待线程执行完毕
    thread_->join();
}

void Thread::setDefaultName()
{
    ThreadNums_++;
    if (name_.empty())
    {
        char buf[32] = {0};
        snprintf(buf, sizeof(buf), "Thread%d", ThreadNums_);
        name_ = buf;
    }
}
