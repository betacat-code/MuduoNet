#include "net_services/Buffer.h"

const char Buffer::kCRLF[] = "\r\n";

//用于HTTP连接的
const char* Buffer::findCRLF() const
{
    const char* crlf = std::search(peek(), beginWrite(), kCRLF, kCRLF+2);
    return crlf == beginWrite() ? NULL : crlf;
}
/*
从fd上读取数据 Poller工作在LT模式，当文件描述符（fd）上有数据可读或可写时，会不断地收到通知
Buffer缓冲区是有大小的， 但是从fd上读取数据的时候 却不知道tcp数据的最终大小
从socket读到缓冲区的方法是使用readv先读至buffer_
Buffer_空间如果不够会读入到栈上65536个字节大小的空间，然后以append的
方式追加入buffer_。既考虑了避免系统调用带来开销，又不影响数据的接收。
*/

ssize_t Buffer::readFd(int fd, int *saveErrno)
{
    char extrabuf[65536] = {0}; // 栈上内存空间 65536/1024 = 64KB
        /*
    struct iovec {
        ptr_t iov_base;
         // iov_base指向的缓冲区存放的是readv所接收的数据或是writev将要发送的数据
        size_t iov_len; 
        // iov_len在各种情况下分别确定了接收的最大长度以及实际写入的长度
    };
    */
   struct iovec vec[2];
   //buffer底层目前所能写的缓存
   const size_t writable = writableBytes();
    // 第一块缓冲区，指向可写空间
    vec[0].iov_base = begin() + writerIndex_;
    vec[0].iov_len = writable;
    // 第二块缓冲区，指向栈空间作为临时缓存
    vec[1].iov_base = extrabuf;
    vec[1].iov_len = sizeof(extrabuf);

    const int iovcnt = (writable < sizeof(extrabuf)) ? 2 : 1;
    const ssize_t n = ::readv(fd, vec, iovcnt);

    if(n<0)
    {
        *saveErrno = errno;
    }
    else if (n <= writable) // Buffer的可写缓冲区已经够存储读出来的数据了
    {
        writerIndex_ += n;
    }
    else
    {
        writerIndex_ = buffer_.size();
        append(extrabuf,n-writable);
    }
    return n;
}

ssize_t Buffer::writeFd(int fd, int *saveErrno)
{
    //这里先不能移位(确保传输正常后 由应用层手动移位)
    ssize_t n = ::write(fd, peek(), readableBytes());
    if (n < 0)
    {
        *saveErrno = errno;
    }
    return n;
}



Buffer::Buffer(size_t initialSize):
    buffer_(kCheapPrepend + initialSize),
    readerIndex_(kCheapPrepend),
    writerIndex_(kCheapPrepend)
    {}


void Buffer::append(const char *data, size_t len)
{
    //先确保有剩余空间
    ensureWritableBytes(len);
    std::copy(data,data+len,beginWrite());
    writerIndex_+=len;
}

void Buffer::append(const std::string &str)
{
    this->append(str.data(),str.size());
}

void Buffer::ensureWritableBytes(size_t len)
{
    //可写的剩余空间不足  把buffer_扩容
    if(writableBytes()<len)
    {
        makeSpace(len);
    }
}

void Buffer::makeSpace(int len)
{   // 整个buffer都不够用
    if (writableBytes() + prependableBytes() < len + kCheapPrepend)
    {
        buffer_.resize(writerIndex_ + len); //直接在后面追加len长度
    }
    else
    {
        // 整个buffer够用，将后面移动到前面继续分配
        size_t readable = readableBytes();//已读入的字符数量
        std::copy(begin() + readerIndex_,begin() + writerIndex_,begin() + kCheapPrepend);
        readerIndex_ = kCheapPrepend;
        writerIndex_ = readerIndex_ + readable;
    }
}

void Buffer::retrieveUntil(const char *end)
{
    retrieve(end - peek());
}

void Buffer::retrieve(size_t len)
{
    //// 应用只读取可读缓冲区数据的一部分
    if(len<readableBytes())
    {
        readerIndex_+=len;
    }
    else //全部读完
    {
        retrieveAll();
    }
}
void Buffer::retrieveAll()
{
    readerIndex_=kCheapPrepend;
    writerIndex_=kCheapPrepend;
}

std::string Buffer::GetBufferAllAsStringDebug()
{
    size_t len=readableBytes();
    std::string res(peek(),len);
    return res;
}

std::string Buffer::retrieveAllAsString()
{
    //把所有的可读 即readableBytes() 读入
    return retrieveAsString(readableBytes());
}

std::string Buffer::retrieveAsString(size_t len)
{
    // peek()可读数据的起始地址
    std::string result(peek(), len);
    retrieve(len);  //复位len
    return result;
}

