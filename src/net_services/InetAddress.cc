#include "net_services/InetAddress.h"
#include <iostream>

InetAddress::InetAddress(uint16_t port, const std::string ip)
{
    //std::cout<<":InetAddress "<<ip<<"\n";
    ::bzero(&addr_, sizeof(addr_));
    addr_.sin_family = AF_INET;//设置地址族为 IPv4
    addr_.sin_port = ::htons(port);//端口号转换成网络字节顺序 大端序
    addr_.sin_addr.s_addr = inet_addr(ip.c_str());
    //std::cout<<":InetAddress "<<this->toIpPort()<<"\n";
}

//
std::string InetAddress::toIp() const
{
    char buf[64] = {0};
    ::inet_ntop(AF_INET, &addr_.sin_addr, buf, sizeof(buf));
    return buf;
}

//将 IP 地址和端口号转换成字符串形式返回。
std::string InetAddress::toIpPort() const
{
    char buf[64]={0};
    //网络字节序转换为点分十进制
    ::inet_ntop(AF_INET, &addr_.sin_addr, buf, sizeof(buf));
    size_t end = ::strlen(buf);
    uint16_t port = ::ntohs(addr_.sin_port);
    sprintf(buf+end, ":%u", port);
    return buf;
}

uint16_t InetAddress::toPort() const
{
    return ::ntohs(addr_.sin_port);
}

