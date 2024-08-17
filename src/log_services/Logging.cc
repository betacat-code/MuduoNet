#include "log_services/Logging.h"
#include "base_components/Timestamp.h"
namespace ThreadInfo
{
    __thread char t_errnobuf[512];
    __thread char t_time[64];
    __thread time_t t_lastSecond;
};

// 根据Level返回Level名字
const char* getLevelName[Logger::LogLevel::LEVEL_COUNT]
{
    "TRACE ",
    "DEBUG ",
    "INFO  ",
    "WARN  ",
    "ERROR ",
    "FATAL ",
};

void Logger::LoggerImpl::formatTime()
{
    Timestamp now = Timestamp::now();
    time_t seconds = static_cast<time_t>(now.microSecondsSinceEpoch() / Timestamp::kMicroSecondsPerSecond);
    int microseconds = static_cast<int>(now.microSecondsSinceEpoch() % Timestamp::kMicroSecondsPerSecond);

    struct tm *tm_time = localtime(&seconds);
    // 写入此线程存储的时间buf中
    snprintf(ThreadInfo::t_time, sizeof(ThreadInfo::t_time), "%4d/%02d/%02d %02d:%02d:%02d",
        tm_time->tm_year + 1900,
        tm_time->tm_mon + 1,
        tm_time->tm_mday,
        tm_time->tm_hour,
        tm_time->tm_min,
        tm_time->tm_sec);
    // 更新最后一次时间调用
    ThreadInfo::t_lastSecond = seconds;

    // muduo使用Fmt格式化整数，这里直接写入buf
    char buf[32] = {0};
    snprintf(buf, sizeof(buf), "%06d ", microseconds);

    // 输出时间，附有微妙(之前是(buf, 6),少了一个空格)
    stream_ << DataTemplate(ThreadInfo::t_time, 17) << DataTemplate(buf, 7);
}

void Logger::LoggerImpl::finish()
{
    //输出了具体内容
    stream_ << " - " << DataTemplate(basename_.data_, basename_.size_) 
            << ':' << line_ << '\n';
}

Logger::LoggerImpl::LoggerImpl(LogLevel level, int savedErrno, const char* file, int line)
    :time_(Timestamp::now()),stream_(),level_(level),line_(line),basename_(file)
{
    this->formatTime();
    //输出了等级
    stream_ << DataTemplate(getLevelName[level], 6);

}


const char* getErrnoMsg(int savedErrno)
{
    //strerror_r 三个参数
    //errnum：表示需要获取错误消息的错误号。
    //buf：用于存储错误消息的缓冲区指针。
    //buflen：表示缓冲区的长度。
    return strerror_r(savedErrno, ThreadInfo::t_errnobuf, sizeof(ThreadInfo::t_errnobuf));
}

Logger::Logger(const char* file, int line)  
    : impl_(INFO, 0, file, line){}

Logger::Logger(const char* file, int line, LogLevel level)
    :impl_(INFO, level, file, line){}

//打印调用函数
Logger::Logger(const char* file, int line, LogLevel level, const char* func)
    :impl_(INFO, level, file, line)
{
    impl_.stream_<<func<<' ';
}


static void defaultOutput(const char* data, int len)
{
    fwrite(data, len, sizeof(char), stdout);
}

static void defaultFlush()
{
    fflush(stdout);
}
Logger::OutputFunc g_output = defaultOutput;
Logger::FlushFunc g_flush = defaultFlush;
Logger::LogLevel g_logLevel=Logger::INFO;
//全局使用g_output g_flush变量 
Logger::~Logger()
{
    impl_.finish();
    // 获取buffer(stream_.buffer_)
    const LogStream::Buffer& buf(this->stream().buffer());
    // 输出(默认向终端输出)
    g_output(buf.data(), buf.length());
    // FATAL情况终止程序
    if (impl_.level_ == FATAL)
    {
        g_flush();
        abort();
    }
}

void Logger::setOutput(OutputFunc out)
{
    g_output=out;
}

void Logger::setFlush(FlushFunc flush)
{
    g_flush=flush;
}

void Logger::setLogLevel(LogLevel level)
{
    g_logLevel=level;
}