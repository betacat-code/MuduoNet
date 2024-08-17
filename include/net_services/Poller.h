#ifndef POLLER_H
#define POLLER_H


#include "base_components/noncopyable.h"
#include "net_services/Channel.h"
#include "base_components/Timestamp.h"
#include <vector>
#include <unordered_map>

class Poller:noncopyable
{
public:
    using ChannelList = std::vector<Channel*>;
    Poller(EventLoop *Loop):ownerLoop_(Loop){};
    virtual ~Poller() = default;

    // 需要交给派生类实现的接口
    virtual Timestamp poll(int timeoutMs, ChannelList *activeChannels) = 0;
    virtual void updateChannel(Channel *channel) = 0;
    virtual void removeChannel(Channel *channel) = 0;

    // 判断 channel是否注册到 poller当中
    bool hasChannel(Channel *channel) const
    {
        auto it = channels_.find(channel->fd());
        return it != channels_.end() && it->second == channel;
    }

protected:  
    using ChannelMap = std::unordered_map<int, Channel*>;
    // 储存 channel 的映射，（sockfd -> channel*）
    ChannelMap channels_;
private:
    EventLoop *ownerLoop_; // 定义Poller所属的事件循环EventLoop

};

#endif