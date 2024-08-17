#include "net_services/Acceptor.h"
#include <functional>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

//创建一个非阻塞的socket
static int createNonblocking()
{
    int sockfd = ::socket(AF_INET, SOCK_STREAM | SOCK_NONBLOCK | SOCK_CLOEXEC, IPPROTO_TCP);
    if (sockfd < 0)
    {
        LOG_FATAL << "listen socket create err " << errno;
    }
    return sockfd;
}

void Acceptor::listen()
{
    // 表示正在监听
    listenning_ = true;
    acceptSocket_.listen();
    // 将acceptChannel的读事件注册到poller
    acceptChannel_.enableReading();
}
// 端口复用
Acceptor::Acceptor(EventLoop *loop, const InetAddress &ListenAddr, bool reuseport) 
    : loop_(loop),
    acceptSocket_(createNonblocking()),
    acceptChannel_(loop, acceptSocket_.fd()),
    listenning_(false)
    {
        LOG_DEBUG << "Acceptor create nonblocking socket, [fd = " << acceptChannel_.fd() << "]";
        acceptSocket_.setReuseAddr(reuseport);
        acceptSocket_.setReusePort(true);
        acceptSocket_.bindAddress(ListenAddr);
        //有新用户的连接，需要执行一个回调函数
        //向acceptor的channel注册回调函数

        acceptChannel_.setReadCallback(std::bind(&Acceptor::handleRead, this));
    }
Acceptor::~Acceptor()
{
    // 把从Poller中感兴趣的事件删除掉
    acceptChannel_.disableAll();    
    // 调用EventLoop->removeChannel => Poller->removeChannel 把Poller的ChannelMap对应的部分删除
    acceptChannel_.remove();       
}

// listenfd有事件发生了，就是有新用户连接了
void Acceptor::handleRead()
{
    InetAddress peerAddr;
    // 接受新连接
    int connfd = acceptSocket_.accept(&peerAddr);
    if (connfd >= 0)
    {
        if (NewConnectionCallback_)
        {
            // 轮询找到subLoop 唤醒并分发当前的新客户端的Channel
            NewConnectionCallback_(connfd, peerAddr); 
        }
        else
        {
            LOG_DEBUG << "no newConnectionCallback() function";
            ::close(connfd);
        }
    }
    else
    {
        LOG_ERROR << "accept() failed";
        if (errno == EMFILE)
        {
            LOG_ERROR << "sockfd reached limit";
        }
    }
}