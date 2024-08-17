#ifndef LOG_STREAM_H
#define LOG_STREAM_H

#include "log_services/FixedBuffer.h"
#include "base_components/noncopyable.h"
#include <string>

class DataTemplate: noncopyable
{
public:
    DataTemplate():data_(nullptr),len_(0){};
    explicit DataTemplate(const char* cur,int len):data_(cur),len_(len){};
    const char* data_;
    int len_;
};

class LogStream : noncopyable
{
public:
    using Buffer = FixedBuffer<kSmallBuffer>;//一条小消息就是4000字节
    
    void append(const char* data, int len) { buffer_.append(data, len); }
    const Buffer& buffer() const { return buffer_; }
    void resetBuffer() { buffer_.reset(); }
    
    // LogStream需要重载运算符
    LogStream& operator<<(short);
    LogStream& operator<<(unsigned short);
    LogStream& operator<<(int);
    LogStream& operator<<(unsigned int);
    LogStream& operator<<(long);
    LogStream& operator<<(unsigned long);
    LogStream& operator<<(long long);
    LogStream& operator<<(unsigned long long);

    LogStream& operator<<(float v);
    LogStream& operator<<(double v);

    LogStream& operator<<(char c);
    LogStream& operator<<(const void* data);
    LogStream& operator<<(const char* str);
    LogStream& operator<<(const unsigned char* str);
    LogStream& operator<<(const std::string& str);
    LogStream& operator<<(const Buffer& buf);

    // (const char*, int)的重载
    LogStream& operator<<(const DataTemplate& g);

private:
    static const int kMaxNumericSize = 48;
    // 对于整型需要特殊处理
    template <typename T>
    void formatInteger(T);

    Buffer buffer_;
};



#endif