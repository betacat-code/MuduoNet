#ifndef ACCEPTOR_H
#define ACCEPTOR_H


#include "base_components/noncopyable.h"
#include "net_services/Socket.h"
#include "net_services/Channel.h"

// Acceptor运行在mainLoop中
// TcpServer发现Acceptor有一个新连接，则将此channel分发给一个subLoop

class Acceptor
{
public:
    // 接受新连接的回调函数
    using NewConnectionCallback = std::function<void(int sockfd, const InetAddress&)>;
    Acceptor(EventLoop *loop, const InetAddress &ListenAddr, bool reuseport);
    ~Acceptor();

    void setNewConnectionCallback(const NewConnectionCallback &cb)
    {
        NewConnectionCallback_ = cb;
    }

    bool listenning() const { return listenning_; }
    void listen();

private:
    void handleRead();

    EventLoop *loop_; // Acceptor用的就是用户定义的BaseLoop
    Socket acceptSocket_;
    Channel acceptChannel_;
    NewConnectionCallback NewConnectionCallback_;
    bool listenning_; // 是否正在监听的标志
};

#endif