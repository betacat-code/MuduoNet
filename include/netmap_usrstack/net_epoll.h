#ifndef __NET_EPOLL_H__
#define __NET_EPOLL_H__

#include <stdint.h>
#include "netmap_usrstack/net_config.h"

typedef enum {
    NET_EPOLLNONE   = 0x0000,    // 无事件
    NET_EPOLLIN     = 0x0001,    // 可读事件
    NET_EPOLLPRI    = 0x0002,    // 高优先级可读事件
    NET_EPOLLOUT    = 0x0004,    // 可写事件
    NET_EPOLLRDNORM = 0x0040,    // 正常数据可读事件
    NET_EPOLLRDBAND = 0x0080,    // 优先数据可读事件
    NET_EPOLLWRNORM = 0x0100,    // 正常数据可写事件
    NET_EPOLLWRBAND = 0x0200,    // 优先数据可写事件
    NET_EPOLLMSG    = 0x0400,    // 消息可用事件
    NET_EPOLLERR    = 0x0008,    // 错误事件
    NET_EPOLLHUP    = 0x0010,    // 挂起事件
    NET_EPOLLRDHUP  = 0x2000,    // 连接中端事件
    NET_EPOLLONESHOT = (1 << 30),// 单次触发事件
    NET_EPOLLET     = (1 << 31) // 边缘触发事件
} net_epoll_type;

typedef enum {
    NET_EPOLL_CTL_ADD = 1,  // 添加事件
    NET_EPOLL_CTL_DEL = 2,  // 删除事件
    NET_EPOLL_CTL_MOD = 3   // 修改事件
} net_epoll_op;

// 定义 epoll 数据联合体
typedef union _net_epoll_data {
    void *ptr;      // 指针类型
    int sockid;     // socket ID 类型
    uint32_t u32;   // 32 位整数类型
    uint64_t u64;   // 64 位整数类型
} net_epoll_data;

// 定义 epoll 事件结构体
typedef struct {
    uint32_t events;    // 事件标志位
    uint64_t data;      // 事件关联数据
} net_epoll_event;


int net_epoll_create(int size);
int net_epoll_ctl(int epid, int op, int sockid, net_epoll_event *event);
int net_epoll_wait(int epid, net_epoll_event *events, int maxevents, int timeout);


#if NET_ENABLE_EPOLL_RB

enum EPOLL_EVENTS {
	EPOLLNONE 	= 0x0000,
	EPOLLIN 	= 0x0001,
	EPOLLPRI	= 0x0002,
	EPOLLOUT	= 0x0004,
	EPOLLRDNORM = 0x0040,
	EPOLLRDBAND = 0x0080,
	EPOLLWRNORM = 0x0100,
	EPOLLWRBAND = 0x0200,
	EPOLLMSG	= 0x0400,
	EPOLLERR	= 0x0008,
	EPOLLHUP 	= 0x0010,
	EPOLLRDHUP 	= 0x2000,
	EPOLLONESHOT = (1 << 30),
	EPOLLET 	= (1 << 31)

};

#define EPOLL_CTL_ADD	1
#define EPOLL_CTL_DEL	2
#define EPOLL_CTL_MOD	3

typedef union epoll_data {
	void *ptr;
	int fd;
	uint32_t u32;
	uint64_t u64;
} epoll_data_t;

struct epoll_event {
	uint32_t events;
	epoll_data_t data;
};

int epoll_create(int size);
int epoll_ctl(int epid, int op, int sockid, struct epoll_event *event);
int epoll_wait(int epid, struct epoll_event *events, int maxevents, int timeout);

int net_epoll_close_socket(int epid);


#endif


#endif



