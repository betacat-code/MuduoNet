#include "base_components/TimerQueue.h"
#include "log_services/Logging.h"

#include <unistd.h>
#include <sys/timerfd.h>

int createTimerfd()
{
    /**
     * CLOCK_MONOTONIC：绝对时间
     * TFD_NONBLOCK：非阻塞
     */
    int timerfd = ::timerfd_create(CLOCK_MONOTONIC,
                                    TFD_NONBLOCK | TFD_CLOEXEC);
    if (timerfd < 0)
    {
        LOG_ERROR << "Failed in timerfd_create";
    }
    return timerfd;
}

TimerQueue::TimerQueue(EventLoop* loop)
    : loop_(loop),
      timerfd_(createTimerfd()),
      timerfdChannel_(loop_, timerfd_),
      timers_()
{
    //唤醒定时器之后的回调函数
    timerfdChannel_.setReadCallback(
        std::bind(&TimerQueue::handleRead, this));
    timerfdChannel_.enableReading();
}

TimerQueue::~TimerQueue()
{   
    timerfdChannel_.disableAll();
    timerfdChannel_.remove();
    ::close(timerfd_);
    // 删除所有定时器
    for (const Entry& timer : timers_)
    {
        //这里timer为指针 手动析构
        delete timer.second;
    }
}

void TimerQueue::addTimer(TimerCallback cb,Timestamp when,double interval)
{
    Timer* timer = new Timer(std::move(cb), when, interval);
    //std::cout<<"addTimer "<<&timerfdChannel_<<"\n";
    loop_->runInLoop(std::bind(&TimerQueue::addTimerInLoop, this, timer));
}

//addTimer实际绑定的函数
void TimerQueue::addTimerInLoop(Timer* timer)
{
    // 是否取代了最早的定时触发时间
    bool eraliestChanged = insert(timer);
    // 需要重新设置timerfd_触发时间
    if (eraliestChanged)
    {
        resetTimerfd(timerfd_, timer->expiration());
    }
}

// 重置timerfd 也就是向其注册红黑树里顺序排名第一（最早的事情）
void TimerQueue::resetTimerfd(int timerfd_, Timestamp expiration)
{
    struct itimerspec newValue;
    memset(&newValue, '\0', sizeof(newValue));
    // 超时时间 - 现在时间
    int64_t microSecondDif = expiration.microSecondsSinceEpoch() - Timestamp::now().microSecondsSinceEpoch();
    if (microSecondDif < 100)
    {
        microSecondDif = 100;
    }

    struct timespec ts;
    ts.tv_sec = static_cast<time_t>(
        microSecondDif / Timestamp::kMicroSecondsPerSecond);
    ts.tv_nsec = static_cast<long>(
        (microSecondDif % Timestamp::kMicroSecondsPerSecond) * 1000);
    newValue.it_value = ts;
    // 此函数会唤醒事件循环
    if (::timerfd_settime(timerfd_, 0, &newValue, nullptr))
    {
        LOG_ERROR << "timerfd_settime faield()";
    }
}


void ReadTimerFd(int timerfd) 
{
    uint64_t read_byte;
    ssize_t readn = ::read(timerfd, &read_byte, sizeof(read_byte));
    
    if (readn != sizeof(read_byte)) {
        LOG_ERROR << "TimerQueue::ReadTimerFd read_size < 0";
    }
}

// 获取到期的定时器
std::vector<TimerQueue::Entry> TimerQueue::getExpired(Timestamp now)
{
    std::vector<Entry> expired;
    Entry sentry(now, nullptr);
    //找到超时的
    TimerList::iterator end = timers_.lower_bound(sentry);
    //复制过去
    std::copy(timers_.begin(), end, back_inserter(expired));
    timers_.erase(timers_.begin(), end);
    
    return expired;
}

// 插入定时器的内部方法
bool TimerQueue::insert(Timer* timer)
{
    bool earliestChanged = false;
    Timestamp when = timer->expiration();
    TimerList::iterator it = timers_.begin();
    if (it == timers_.end() || when < it->first)
    {
        // 说明最早的定时器已经被替换了
        earliestChanged = true;
    }

    // 定时器管理红黑树插入此新定时器
    timers_.insert(Entry(when, timer));

    return earliestChanged;
}

//expired已从set里取出 存在指针需要手动释放
void TimerQueue::reset(const std::vector<Entry>& expired, Timestamp now)
{
    Timestamp nextExpire;
    for(const Entry& it:expired)
    {
        if(it.second->repeat())
        {
            auto timer = it.second;
            timer->restart(Timestamp::now());
            insert(timer);
        }
        else
        {
            delete it.second;
        }
        //定时器队列不为空 就重新调整一下(reset里可能存在放入定时器队列的东西)
        if(!timers_.empty())
        {
            resetTimerfd(timerfd_,(timers_.begin()->second)->expiration());
        }
    }
}

void TimerQueue::handleRead()
{
    Timestamp now = Timestamp::now();
    ReadTimerFd(timerfd_);
    
    std::vector<Entry> expired = getExpired(now);

    // 遍历到期的定时器，调用回调函数
    callingExpiredTimers_ = true;
    for (const Entry& it : expired)
    {
        it.second->run();
    }
    callingExpiredTimers_ = false;
    //重置定时器
    reset(expired,now);
}