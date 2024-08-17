#ifndef __NET_EPOLL_INNER_H__
#define __NET_EPOLL_INNER_H__

#include "netmap_usrstack/net_epoll.h"
#include "netmap_usrstack/net_socket.h"
#include "netmap_usrstack/net_buffer.h"
#include "netmap_usrstack/net_header.h"


typedef struct _net_epoll_stat {
    uint64_t calls;        // 记录调用次数
    uint64_t waits;        // 记录等待次数
    uint64_t wakes;        // 记录唤醒次数

    uint64_t issued;       // 记录发出的事件数量
    uint64_t registered;   // 记录注册的事件数量
    uint64_t invalidated;  // 记录失效的事件数量
    uint64_t handled;      // 记录处理的事件数量
} net_epoll_stat;

// 包含事件及其对应套接字标识的结构体
typedef struct _net_epoll_event_int {
    net_epoll_event ev;    // epoll 事件结构体
    int sockid;            // 套接字标识符
} net_epoll_event_int;

typedef enum {
	USR_EVENT_QUEUE = 0, // 用户事件队列
	USR_SHADOW_EVENT_QUEUE = 1,  // 用户影子事件队列
	NET_EVENT_QUEUE = 2 // 网络事件队列
} net_event_queue_type;


typedef struct _net_event_queue {
    net_epoll_event_int *events;  // 指向事件数组的指针
    int start;                    // 队列的起始索引
    int end;                      // 队列的结束索引
    int size;                     // 队列的大小
    int num_events;               // 当前队列中事件的数量
} net_event_queue;

typedef struct _net_epoll {
    net_event_queue *usr_queue;          // 用户事件队列
    net_event_queue *usr_shadow_queue;   // 用户影子事件队列
    net_event_queue *queue;              // 网络事件队列

    uint8_t waiting;                     // 表示当前是否正在等待事件
    net_epoll_stat stat;                 // epoll 统计信息

    pthread_cond_t epoll_cond;           // 条件变量，用于线程同步
    pthread_mutex_t epoll_lock;          // 互斥锁，用于保护对 epoll 结构体的访问
} net_epoll;

// 添加事件到指定的事件队列中
int net_epoll_add_event(net_epoll *ep, int queue_type, struct _net_socket_map *socket, uint32_t event);

// 关闭指定的 epoll 套接字
int net_close_epoll_socket(int epid);

// 刷新事件队列中的事件
int net_epoll_flush_events(uint32_t cur_ts);


// 启动自生成的epoll机制
#if NET_ENABLE_EPOLL_RB

struct epitem {
	RB_ENTRY(epitem)   rbn;    // 红黑树节点
	LIST_ENTRY(epitem) rdlink; // 就绪队列节点
	int rdy; // 存储在链表中的标志，表示是否准备好
	int sockfd;
	struct epoll_event event; 
};

// 比较两个epitem的sockfd，用于红黑树的排序
static int sockfd_cmp(struct epitem *ep1, struct epitem *ep2) {
	if (ep1->sockfd < ep2->sockfd) return -1;
	else if (ep1->sockfd == ep2->sockfd) return 0;
	return 1;
}

// 红黑树，节点类型为epitem
RB_HEAD(_epoll_rb_socket, epitem);

// 使用sockfd_cmp函数生成红黑树 
RB_GENERATE_STATIC(_epoll_rb_socket, epitem, rbn, sockfd_cmp);

typedef struct _epoll_rb_socket ep_rb_tree;


struct eventpoll {
	ep_rb_tree rbr;  // 红黑树的根节点
	int rbcnt; // 红黑树中节点的计数
	
	LIST_HEAD( ,epitem) rdlist; // 就绪链表的头节点
	int rdnum; // 就绪链表中的节点数量

	int waiting; // 表示当前是否有线程在等待事件

	pthread_mutex_t mtx; // 用于红黑树更新的互斥锁
	pthread_spinlock_t lock; // 用于就绪链表更新的自旋锁
	
	pthread_cond_t cond; // 用于事件阻塞的条件变量
	pthread_mutex_t cdmtx; // 用于条件变量的互斥锁
};

// epoll事件回调函数
int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event);



#endif



#endif



