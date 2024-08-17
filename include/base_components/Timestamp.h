#ifndef TIME_STAMP_H
#define TIME_STAMP_H

#include <iostream>
#include <string>
#include <sys/time.h>

class Timestamp
{
private:
    int64_t microSecondsSinceEpoch_;;
public:
    Timestamp(): microSecondsSinceEpoch_(0){}
    explicit Timestamp(int64_t microSecondsSinceEpoch): 
        microSecondsSinceEpoch_(microSecondsSinceEpoch){}
    
    // 获取当前时间戳
    static inline Timestamp now()
    {
        struct timeval tv;
        // 获取微妙和秒
        // 在x86-64平台gettimeofday()已不是系统调用,不会陷入内核, 多次调用不会有性能损失.
        gettimeofday(&tv, NULL);
        int64_t seconds = tv.tv_sec;
        // 转换为微妙
        return Timestamp(seconds * kMicroSecondsPerSecond + tv.tv_usec);
    }

    //格式, "%4d年%02d月%02d日 星期%d %02d:%02d:%02d.%06d",时分秒.微秒
    std::string toFormattedString(bool showMicroseconds = false) const;

    //返回当前时间戳的微妙
    inline int64_t microSecondsSinceEpoch() const { return microSecondsSinceEpoch_; }

    time_t secondsSinceEpoch() const
    { 
        return static_cast<time_t>(microSecondsSinceEpoch_ / kMicroSecondsPerSecond); 
    }

    // 失效的时间戳，返回一个值为0的Timestamp
    static Timestamp invalid()
    {
        return Timestamp();
    }

    // 1秒=1000*1000微妙
    static const int kMicroSecondsPerSecond = 1000 * 1000;
};

//重载比较
inline bool operator<(Timestamp lhs, Timestamp rhs)
{
    return lhs.microSecondsSinceEpoch() < rhs.microSecondsSinceEpoch();
}

inline bool operator==(Timestamp lhs, Timestamp rhs)
{
    return lhs.microSecondsSinceEpoch() == rhs.microSecondsSinceEpoch();
}

// 如果是重复定时任务就会对此时间戳进行增加。
inline Timestamp addTime(Timestamp timestamp, double seconds)
{
    // 将延时的秒数转换为微妙
    int64_t delta = static_cast<int64_t>(seconds * Timestamp::kMicroSecondsPerSecond);
    // 返回新增时后的时间戳
    return Timestamp(timestamp.microSecondsSinceEpoch() + delta);
}


#endif