#ifndef __NET_SOCKET_H__
#define __NET_SOCKET_H__

//网络套接字的管理和配置
#include "netmap_usrstack/net_buffer.h"
#include "netmap_usrstack/net_tcp.h"
#include "netmap_usrstack/net_config.h"

#include <pthread.h>


typedef struct _net_socket_map {
	int id;
	int socktype;
	uint32_t opts;

	struct sockaddr_in s_addr;
	//根据套接字类型存储不同的指针（TCP流、TCP监听、epoll或epoll结构体）
	union {
		struct _net_tcp_stream *stream;
		struct _net_tcp_listener *listener;
#if NET_ENABLE_EPOLL_RB
		void *ep;
#else
		struct _net_epoll *ep;
#endif
	};

	uint32_t epoll;
	uint32_t events;
	uint64_t ep_data;

	TAILQ_ENTRY(_net_socket_map) free_smap_link; //管理空闲套接字映射
} net_socket_map;  


enum net_socket_opts{
	NET_TCP_NONBLOCK = 0x01, //套接字设置为非阻塞模式
	NET_TCP_ADDR_BIND = 0x02, // 套接字地址绑定选项
};

net_socket_map *net_allocate_socket(int socktype, int need_lock);
void net_free_socket(int sockid, int need_lock);
net_socket_map *net_get_socket(int sockid);


//10M套接字模块
#if NET_ENABLE_SOCKET_C10M


struct _net_socket {
	int id;	
	int socktype;

	uint32_t opts;
	struct sockaddr_in s_addr;

	union {
		struct _net_tcp_stream   *stream;
		struct _net_tcp_listener *listener;
		void *ep;
	};
	struct _net_socket_table *socktable;
};

//管理套接字
struct _net_socket_table {
	size_t max_fds;
	int cur_idx;
	struct _net_socket **sockfds;
	unsigned char *open_fds; //管理套接字的状态，
	pthread_spinlock_t lock; //自旋锁
};

struct _net_socket* net_socket_allocate(int socktype);

void net_socket_free(int sockid);

struct _net_socket* net_socket_get(int sockid);

struct _net_socket_table * net_socket_init_fdtable(void);

int net_socket_close_listening(int sockid);

int net_socket_close_stream(int sockid);

#endif

#endif


