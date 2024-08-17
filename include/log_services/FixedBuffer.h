#ifndef FIXED_BUFFER_H
#define FIXED_BUFFER_H

#include <assert.h>
#include <string.h> // memcpy
#include <strings.h>
#include <string>
#include "base_components/noncopyable.h"
#define kSmallBuffer 4000 //一条消息的长度
#define kLargeBuffer 4000*1000

template<int SIZE>
class FixedBuffer:noncopyable
{
private:
    const char* end() const { return data_ + sizeof(data_); }
    char data_[SIZE];
    char* cur_; //操作缓存区data的指针
public:
    FixedBuffer():cur_(data_){};
    const char* data() const { return data_; }
    int length() const { return static_cast<int>(end() - data_); }
    char* current() { return cur_; }
    int avail() const { return static_cast<int>(end() - cur_); }
    void add(size_t len) { cur_ += len; }
    void reset() { cur_ = data_; }
    void bzero() { memset(data_,0,sizeof(data_)); }
    std::string toString() const { return std::string(data_, length()); }
    void append(const char* buf, size_t len)
    {
        if (static_cast<size_t>(avail()) > len)
        {
            memcpy(cur_, buf, len);
            cur_ += len;
        }
        else
        {
            printf("FixedBuffer avail error\n");
        }
    }
};

#endif