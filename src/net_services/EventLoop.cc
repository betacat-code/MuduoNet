#include "net_services/EventLoop.h"
#include <sys/eventfd.h>
#include <unistd.h>

// 防止一个线程创建多个EventLoop (thread_local)

__thread EventLoop *t_loopInThisThread = nullptr;

// 定义默认的Poller IO复用接口的超时时间
const int kPollTimeMs = 10000;

//eventfd使用
int createEventfd()
{
    int evfd = ::eventfd(0, EFD_NONBLOCK | EFD_CLOEXEC);
    if (evfd < 0)
    {
        LOG_FATAL << "eventfd error: " << errno;
    }
    return evfd;
}

EventLoop::EventLoop() : 
    looping_(false),
    quit_(false),
    callingPendingFunctors_(false),
    threadId_(syscall(SYS_gettid)),
    poller_(new EPollPoller(this)),
    //timerQueue_(new TimerQueue(this)), 在外面声明 绑定
    wakeupFd_(createEventfd()),
    wakeupChannel_(new Channel(this, wakeupFd_)),
    currentActiveChannel_(nullptr)
{
    LOG_DEBUG << "EventLoop created " << this << " the index is " << threadId_;
    LOG_DEBUG << "EventLoop created wakeupFd " << wakeupChannel_->fd();
    if (t_loopInThisThread)
    {
        LOG_FATAL << "Another EventLoop" << t_loopInThisThread << " exists in this thread " << threadId_;
    }
    else
    {
        t_loopInThisThread = this;
    }

    // 设置wakeupfd的事件类型以及发生事件的回调函数
    wakeupChannel_->setReadCallback(std::bind(&EventLoop::handleRead, this));
    // 每一个EventLoop都将监听wakeupChannel的EPOLLIN事件
    wakeupChannel_->enableReading();
}

void EventLoop::handleRead()
{
    uint64_t one = 1;
    ssize_t n = read(wakeupFd_, &one, sizeof(one));
    if (n != sizeof(one))
    {
        LOG_ERROR << "EventLoop::handleRead() reads " << n << " bytes instead of 8";
    }
}

void EventLoop::loop()
{
    looping_=true;
    quit_=false;
    LOG_INFO << "EventLoop " << this << " start looping";
    while(!quit_)
    {
        activeChannels_.clear();
        //读取了poller里有事件的channels
        pollReturnTime_ = poller_->poll(kPollTimeMs, &activeChannels_);
        for (Channel *channel : activeChannels_)
        {
            //处理事件
            channel->handleEvent(pollReturnTime_);
        }
        // 执行当前EventLoop事件循环需要处理的回调操作
        //IO thread：mainLoop accept fd 打包成 chennel 分发给 subLoop
        //mainLoop实现注册一个回调，交给subLoop来执行
        //wakeup subLoop 之后，让其执行注册的回调操作
        //这些回调函数在 std::vector<Functor> pendingFunctors_; 之中
        doPendingFunctors();
    }
    looping_=false;
}

void EventLoop::quit()
{
    quit_ = true;
    //有可能是别的线程调用quit(调用线程不是生成EventLoop对象的那个线程)
    //比如在工作线程(subLoop)中调用了IO线程(mainLoop),这种情况唤醒主线程
    if (isInLoopThread())
    {
        wakeup();
    }
}

// 在当前eventLoop中执行回调函数
void EventLoop::runInLoop(Functor cb)
{
    // 每个EventLoop都保存创建自己的线程tid
    // 获取当前执行线程的tid然后和EventLoop保存的进行比较
    if (isInLoopThread())
    {
        cb();
    }
    // 在非当前eventLoop线程中执行回调函数，需要唤醒evevntLoop所在线程
    else
    {
        queueInLoop(cb);
    }
}

void EventLoop::queueInLoop(Functor cb)
{
    {
        std::unique_lock<std::mutex> lock(mutex_);
        pendingFunctors_.emplace_back(cb); // 使用了std::move
    }
    // 唤醒相应的，需要执行上面回调操作的loop线程
    if(!isInLoopThread()||callingPendingFunctors_)
    {
        wakeup();
    }
}

void EventLoop::wakeup()
{
    uint64_t one = 1;
    ssize_t n = write(wakeupFd_, &one, sizeof(one));
    if (n != sizeof(one))
    {
        LOG_ERROR << "EventLoop::wakeup writes " << n << " bytes instead of 8";
    }
}


void EventLoop::doPendingFunctors()
{
    std::vector<Functor> functors;
    callingPendingFunctors_ = true;

    //局部加锁 交换回调函数 否则加锁遍历 其他线程无法注册回调

    {
        std::unique_lock<std::mutex> lock(mutex_);
        functors.swap(pendingFunctors_);
    }

    for (const Functor &functor : functors)
    {
        functor();
    }

    callingPendingFunctors_ = false;
}

void EventLoop::updateChannel(Channel *channel)
{
    poller_->updateChannel(channel);
}

void EventLoop::removeChannel(Channel *channel)
{
    poller_->removeChannel(channel);
}

bool EventLoop::hasChannel(Channel *channel)
{
    return poller_->hasChannel(channel);    
}

EventLoop::~EventLoop()
{
    // channel移除所有感兴趣事件
    wakeupChannel_->disableAll();
    // 将channel从EventLoop中删除
    wakeupChannel_->remove();
    // 关闭 wakeupFd_
    ::close(wakeupFd_);
    // 指向EventLoop指针为空
    t_loopInThisThread = nullptr;
}




