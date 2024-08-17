#ifndef TIMER_H
#define TIMER_H

#include "base_components/noncopyable.h"
#include "Timestamp.h"
#include <functional>

class Timer:noncopyable
{
public:
    using TimerCallback = std::function<void()>;
     Timer(TimerCallback fun, Timestamp when, double interval)
        : callback_(move(fun)),
          expiration_(when),
          interval_(interval),
          repeat_(interval > 0.0) // 一次性定时器设置为0
    {
    }

    void run() const{ callback_();}
    Timestamp expiration() const  { return expiration_; }
    bool repeat() const { return repeat_; }

    void restart(Timestamp now)
    {
        if(this->repeat_)  this->expiration_= addTime(expiration_,interval_);
        else this->expiration_= Timestamp();
    }

private:
    const TimerCallback callback_;  // 定时器回调函数
    Timestamp expiration_;          // 下一次的超时时刻
    const double interval_;         // 超时时间间隔，如果是一次性定时器，该值为0
    const bool repeat_;             // 是否重复(false 表示是一次性定时器)
};

#endif