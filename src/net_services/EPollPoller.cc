#include "net_services/EPollPoller.h"
#include <string>

const int kNew = -1;    // 某个channel还没添加至Poller          
// channel的成员index_初始化为-1
const int kAdded = 1;   // 某个channel已经添加至Poller

const int kDeleted = 2; 
// 某个channel目前没有感兴趣的事情，从Poller删除 但map中还存在相关结构

EPollPoller::EPollPoller(EventLoop *loop) :
        Poller(loop), // 传给基类
        epollfd_(::epoll_create1(EPOLL_CLOEXEC)),
        events_(kInitEventListSize)
{
    if (epollfd_ < 0)
    {
        LOG_FATAL << "epoll_create() error:" << errno;
    }
}

EPollPoller::~EPollPoller()
{
    ::close(epollfd_);
}

//不涉及channel的状态修改 只修改epoll上的状态
void EPollPoller::update(int operation, Channel *channel)
{
    epoll_event event;
    ::memset(&event,0,sizeof(event));
    int fd=channel->fd();
    event.events=channel->events();
    //联合体 tmd 只能赋值fd ptr中的一个 不能两个都赋值
    event.data.ptr=channel;
    //event.data.fd=fd;
    if(::epoll_ctl(epollfd_,operation,fd,&event)<0)
    {
        if (operation == EPOLL_CTL_DEL)
        {
            LOG_ERROR << "epoll_ctl() del error:" << errno;
        }
        else
        {
            LOG_FATAL << "epoll_ctl add/mod error:" << errno;
        }

    }
}


// 填写活跃的连接
void EPollPoller::fillActiveChannels(int numEvents, 
    ChannelList *activeChannels) const
{
    for (int i = 0; i < numEvents; ++i)
    {
        Channel *channel = static_cast<Channel*>(events_[i].data.ptr);
        channel->set_revents(events_[i].events); //返回poller发生的事情
        activeChannels->push_back(channel);
    }
}

//poller 删除channel 即需要在map里清除掉
void EPollPoller::removeChannel(Channel *channel)
{
    int fd=channel->fd();
    this->channels_.erase(fd);

    int index=channel->index();
    if(index==kAdded)
    {
        // 如果此fd已经被添加到Poller中，则还需从epoll对象中删除
        update(EPOLL_CTL_DEL,channel);
    }
    channel->set_index(kNew); //设置为未注册 
}

void EPollPoller::updateChannel(Channel *channel)
{
    int index=channel->index();
    if(index==kNew || index==kDeleted)
    {
        if(index==kNew)
        {
            int fd=channel->fd();
            this->channels_[fd]=channel;
        }
        channel->set_index(kAdded);
        update(EPOLL_CTL_ADD, channel);
    }
    else
    {
        //没有感兴趣的事情就先删掉
        if(channel->isNoneEvent())
        {
            update(EPOLL_CTL_DEL, channel);
            channel->set_index(kDeleted);
        }
        else //存在事情但被修改了
        {
            update(EPOLL_CTL_MOD, channel);
        }
    }
}

Timestamp EPollPoller::poll(int timeoutMs, ChannelList *activeChannels)
{
    size_t numEvents = ::epoll_wait(epollfd_, &(*events_.begin()), 
                        static_cast<int>(events_.size()), timeoutMs);
    int saveErrno = errno;
    Timestamp now(Timestamp::now());
    if(numEvents > 0)
    {
        fillActiveChannels(numEvents,activeChannels);
        // 对events_进行扩容操作
        if (numEvents == events_.size())
        {
            events_.resize(events_.size() * 2);
        }
    }
    else if(numEvents == 0)
    {
        LOG_DEBUG << "timeout!";
    }
    else
    {
         // 不是终端错误
        if (saveErrno != EINTR)
        {
            errno = saveErrno;
            LOG_ERROR << "EPollPoller::poll() failed";
        }
    }
    return now;
}
