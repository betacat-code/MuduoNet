#include "net_services/Channel.h"
#include "net_services/EventLoop.h"

const int Channel::kNoneEvent = 0;
const int Channel::kReadEvent = EPOLLIN | EPOLLPRI;
const int Channel::kWriteEvent = EPOLLOUT;

Channel::Channel(EventLoop *loop, int fd)
    :   loop_(loop),
        fd_(fd),
        events_(0),
        revents_(0),
        index_(-1), //标明是否在poller上注册？
        tied_(false)
{

}

// 在TcpConnection建立时候 调用
void Channel::tie(const std::shared_ptr<void> &obj)
{
    // weak_ptr 指向 obj
    tie_ = obj;
    tied_ = true;
}

 void Channel::update()
{
    //std::cout<<"Channel::update "<<this <<"  "<<this->fd_<<"\n";
    //TODO:Channel::update()
    // 通过该channel所属的EventLoop，调用poller对应的方法，注册fd的events事件
    loop_->updateChannel(this);
}

void Channel::remove()
{
    loop_->removeChannel(this);
}


// fd得到poller通知以后，去处理事件
void Channel::handleEvent(Timestamp receiveTime)
{
    /**
     * 调用了Channel::tie得会设置tid_=true
     * 而TcpConnection::connectEstablished会调用channel_->tie(shared_from_this());
     * 所以对于TcpConnection::channel_ 需要多一份强引用的保证以免用户误删TcpConnection对象
     */
    if (tied_)
    {
        // 变成shared_ptr增加引用计数，防止误删
        std::shared_ptr<void> guard = tie_.lock();
        if (guard)
        {
            handleEventWithGuard(receiveTime);
        }
        // guard为空情况，说明Channel的TcpConnection对象已经不存在了
    }
    else 
    {
        handleEventWithGuard(receiveTime);
    }
}



void Channel::handleEventWithGuard(Timestamp receiveTime)
{    
    // 对端关闭事件
    // 当TcpConnection对应Channel，通过shutdown关闭写端，epoll触发EPOLLHUP
    if ((revents_ & EPOLLHUP) && !(revents_ & EPOLLIN))
    {
        // 确认是否拥有回调函数
        if (closeCallback_)
        {
            closeCallback_();
        }
    }

    // 错误事件
    if (revents_ & (EPOLLERR))
    {
        LOG_ERROR << "the fd = " << this->fd();
        if (errorCallback_)
        {
            errorCallback_();
        }
    }

    // 读事件
    if (revents_ & (EPOLLIN | EPOLLPRI))
    {
        LOG_DEBUG << "channel have read events, the fd = " << this->fd();
        if (readCallback_)
        {
            LOG_DEBUG << "channel call the readCallback_(), the fd = " << this->fd();
            readCallback_(receiveTime);
        }
    }

    // 写事件
    if (revents_ & EPOLLOUT)
    {
        if (writeCallback_)
        {
            writeCallback_();
        }
    }
}
