#ifndef BUFFER_H
#define BUFFER_H

#include <errno.h>
#include <sys/uio.h>
#include <unistd.h>

#include "log_services/Logging.h"

#include <vector>
#include <string>
#include <algorithm>


/// +-------------------+------------------+------------------+
/// | prependable bytes |  readable bytes  |  writable bytes  |
/// |                   |     (CONTENT)    |                  |
/// +-------------------+------------------+------------------+
/// |                   |                  |                  |
/// 0      <=      readerIndex   <=   writerIndex    <=     size


class Buffer
{
public:
    // prependable 初始大小，readIndex 初始位置
    static const size_t kCheapPrepend = 8;
    // writeable 初始大小，writeIndex 初始位置  
    // 刚开始 readerIndex 和 writerIndex 处于同一位置
    static const size_t kInitialSize = 1024;
    explicit Buffer(size_t initialSize = kInitialSize);
    //kCheapPrepend | reader | writer |

    //可读
    size_t readableBytes() const { return writerIndex_ - readerIndex_; }
    //可写
    size_t writableBytes() const { return buffer_.size() - writerIndex_; }
    size_t prependableBytes() const { return readerIndex_; }
    // 返回缓冲区中可读数据的起始地址
    const char* peek() const{return begin() + readerIndex_;}

    // 把[data, data+len]内存上的数据添加到缓冲区中
    void append(const char *data, size_t len);
    void append(const std::string &str);
    
    //确保有足够的空间写下
    void ensureWritableBytes(size_t len);

    //writer指针
    char* beginWrite(){return begin() + writerIndex_;}
    const char* beginWrite()const {return begin() + writerIndex_;}

    //复位操作
    void retrieveUntil(const char *end); //复位到end
    void retrieve(size_t len);//读指针向后移动len个字符
    void retrieveAll();//全部读完 都复位

    //提取缓冲区内容
    std::string GetBufferAllAsStringDebug(); //dubug使用 读取全部缓冲区内容
    std::string retrieveAllAsString();//读取全部缓冲区（写 读 指针复位）
    std::string retrieveAsString(size_t len);//读取一定数量

    // 从fd上读取数据
    ssize_t readFd(int fd, int *saveErrno);
    // 通过fd发送数据
    ssize_t writeFd(int fd, int *saveErrno);

    const char* findCRLF() const;


private:
    char* begin(){return &(*buffer_.begin());}
    //该函数由peek()调用
    const char* begin()const {return &(*buffer_.begin());}
    void makeSpace(int len);


    std::vector<char> buffer_;
    size_t readerIndex_;
    size_t writerIndex_;
    static const char kCRLF[];
};

#endif