#include "netmap_usrstack/net_epoll_inner.h"
#include "netmap_usrstack/net_header.h"
#include "netmap_usrstack/net_socket.h"

#include <hugetlbfs.h>
#include <pthread.h>
#include <errno.h>

extern net_tcp_manager *net_get_tcp_manager(void);

//可选单线程 无需加锁
net_socket_map *net_allocate_socket(int socktype, int need_lock) {
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (tcp == NULL) {
		assert(0);
		return NULL;
	}

	if (need_lock) {
		pthread_mutex_lock(&tcp->ctx->smap_lock);
	}

	//获取一个空闲的套接字
	net_socket_map *socket = NULL;
	while (socket == NULL) {
		socket = TAILQ_FIRST(&tcp->free_smap);
		if (!socket) {
			if (need_lock) {
				pthread_mutex_unlock(&tcp->ctx->smap_lock);
			}
			printf("The concurrent sockets are at maximum.\n");
			return NULL;
		}
		TAILQ_REMOVE(&tcp->free_smap, socket, free_smap_link);
		//如果获取到的套接字有事件，则说明它还在使用中
		//将其重新放回队列，并继续尝试获取新的空闲套接字
		if (socket->events) {
			printf("There are still not invalidate events remaining.\n");
			TAILQ_INSERT_TAIL(&tcp->free_smap, socket, free_smap_link);
			socket = NULL;
		}
	}

	if (need_lock) {
		pthread_mutex_unlock(&tcp->ctx->smap_lock);
	}
	socket->socktype = socktype;
	socket->opts = 0;
	socket->stream = NULL;
	socket->epoll = 0;
	socket->events = 0;

	memset(&socket->s_addr, 0, sizeof(struct sockaddr_in));
	memset(&socket->ep_data, 0, sizeof(net_epoll_data));

	return socket;
	
}


void net_free_socket(int sockid, int need_lock) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	net_socket_map *socket = &tcp->smap[sockid];

	//如果套接字已经被标记为未使用，则直接返回
	if (socket->socktype == NET_TCP_SOCK_UNUSED) {
		return ;
	}
	//清空相关字段
	socket->socktype = NET_TCP_SOCK_UNUSED;
	socket->socktype = NET_EPOLLNONE;
	socket->events = 0;

	if (need_lock) {
		pthread_mutex_lock(&tcp->ctx->smap_lock);
	}
	//重新插入到 free_smap 队列
	tcp->smap[sockid].stream = NULL;
	TAILQ_INSERT_TAIL(&tcp->free_smap, socket, free_smap_link);

	if (need_lock) {
		pthread_mutex_unlock(&tcp->ctx->smap_lock);
	}
}

//获取指定 sockid 的套接字映射
net_socket_map *net_get_socket(int sockid) {
	//检查 sockid 是否在有效范围
#if 1	
	if (sockid < 0 || sockid >= NET_MAX_CONCURRENCY) {
		errno = EBADF;
		return NULL;
	}
#endif
	net_tcp_manager *tcp = net_get_tcp_manager();
	net_socket_map *socket = &tcp->smap[sockid];

	return socket;
}                     

//以下用于处理大规模套接字文件描述符（FD）的内存管理模块

#if NET_ENABLE_SOCKET_C10M

//分配和初始化一个套接字文件描述符表，以支持大规模套接字操作（10M）
struct _net_socket_table * net_socket_allocate_fdtable(void) {
	
	struct _net_socket_table *sock_table = (struct _net_socket_table*)calloc(1, sizeof(struct _net_socket_table));
	if (sock_table == NULL) {
		errno = -ENOMEM;
		return NULL;
	}

	size_t total_size = NET_SOCKFD_NR * sizeof(struct _net_socket *);
#if (NET_SOCKFD_NR > 1024)
    // 使用大页内存分配文件描述符数组
	sock_table->sockfds = (struct _net_socket **)get_huge_pages(total_size, GHP_DEFAULT);
	if (sock_table->sockfds == NULL) {
		errno = -ENOMEM;
		free(sock_table);
		return NULL;
	}
#else
     // 使用 posix_memalign 进行页面对齐的内存分配
	int res = posix_memalign((void **)&sock_table->sockfds, getpagesize(), total_size);
	if (res != 0) {
		errno = -ENOMEM;
		free(sock_table);
		return NULL;
	}
#endif
     // 计算存储已打开文件描述符状态所需的字节数
	sock_table->max_fds = (NET_SOCKFD_NR % NET_BITS_PER_BYTE ? NET_SOCKFD_NR / NET_BITS_PER_BYTE + 1 : NET_SOCKFD_NR / NET_BITS_PER_BYTE);
	
	sock_table->open_fds = (unsigned char*)calloc(sock_table->max_fds, sizeof(unsigned char));
	 // 分配失败；设置 errno 为 ENOMEM，释放之前分配的内存并返回 NULL
	if (sock_table->open_fds == NULL) {
		errno = -ENOMEM;
#if (NET_SOCKFD_NR > 1024)
		free_huge_pages(sock_table->sockfds);
#else
		free(sock_table->sockfds);
#endif
		free(sock_table);
		return NULL;
	}

	if (pthread_spin_init(&sock_table->lock, PTHREAD_PROCESS_SHARED)) {
		errno = -EINVAL;
		free(sock_table->open_fds);
#if (NET_SOCKFD_NR > 1024)
		free_huge_pages(sock_table->sockfds);
#else
		free(sock_table->sockfds);
#endif
		free(sock_table);

		return NULL;
	}

	return sock_table;
}

//释放与套接字表关联的资源。
void net_socket_free_fdtable(struct _net_socket_table *fdtable) {
	// 销毁自旋锁
	pthread_spin_destroy(&fdtable->lock);
	
	// 释放为已打开文件描述符状态分配的内存
	free(fdtable->open_fds);

	// 释放为文件描述符数组分配的内存
#if (NET_SOCKFD_NR > 1024)
	free_huge_pages(fdtable->sockfds);
#else
	free(fdtable->sockfds);
#endif

	free(fdtable);
}


//获取套接字表
struct _net_socket_table *net_socket_get_fdtable(void) {
	// 从 TCP 管理器获取套接字表
	net_tcp_manager *tcp = net_get_tcp_manager();
	return tcp->fdtable;
}

//初始化 分配一个新的套接字表
struct _net_socket_table * net_socket_init_fdtable(void) {
	return net_socket_allocate_fdtable();
}

//查找未使用的文件描述符 
int net_socket_find_id(unsigned char *fds, int start, size_t max_fds) {

	size_t i = 0;
	for (i = start;i < max_fds;i ++) {
		if (fds[i] != 0xFF) {
			break;
		}
	}
	// 如果所有位置都已被使用，则返回 -1
	if (i == max_fds) return -1;
	// 查找第一个未使用的比特位
	int j = 0;
	char byte = fds[i];
	while (byte % 2) {
		byte /= 2;
		j ++;
	}
	// 返回文件描述符的实际 ID
	return i * NET_BITS_PER_BYTE + j;
}

//将指定的文件描述符 ID 标记为未使用
char net_socket_unuse_id(unsigned char *fds, size_t idx) {

	int i = idx / NET_BITS_PER_BYTE;// 计算字节索引
	int j = idx % NET_BITS_PER_BYTE;// 计算位索引

	char byte = 0x01 << j; // 计算要清除的比特位
	fds[i] &= ~byte;  // 清除指定的比特位

	return fds[i];
}

//计算文件描述符  所在的字节索引
int net_socket_set_start(size_t idx) {
	return idx / NET_BITS_PER_BYTE;
}

//将指定的文件描述符 标记为已使用
char net_socket_use_id(unsigned char *fds, size_t idx) {

	int i = idx / NET_BITS_PER_BYTE;
	int j = idx % NET_BITS_PER_BYTE;

	char byte = 0x01 << j;

	fds[i] |= byte;

	return fds[i];
}

// 分配一个新的网络套接字
struct _net_socket* net_socket_allocate(int socktype) {

	struct _net_socket *s = (struct _net_socket*)calloc(1, sizeof(struct _net_socket));
	if (s == NULL) {
		errno = -ENOMEM;// 分配内存失败
		return NULL;
	}

	struct _net_socket_table *sock_table = net_socket_get_fdtable();
	

	pthread_spin_lock(&sock_table->lock);
	
	// 查找一个可用的套接字 ID
	s->id = net_socket_find_id(sock_table->open_fds, sock_table->cur_idx, sock_table->max_fds);
	if (s->id == -1) {
		pthread_spin_unlock(&sock_table->lock);
		errno = -ENFILE;
		return NULL;
	}

	// 设置当前索引
	sock_table->cur_idx = net_socket_set_start(s->id);
	char byte = net_socket_use_id(sock_table->open_fds, s->id);
	
	sock_table->sockfds[s->id] = s;

	net_trace_socket("net_socket_allocate --> net_socket_use_id : %x\n", byte);
	
	pthread_spin_unlock(&sock_table->lock);

	// 初始化套接字属性
	s->socktype = socktype;
	s->opts = 0;
	s->socktable = sock_table;
	s->stream = NULL;

	memset(&s->s_addr, 0, sizeof(struct sockaddr_in));

	UNUSED(byte);

	return s;
}

// 释放指定的套接字
void net_socket_free(int sockid) {

	struct _net_socket_table *sock_table = net_socket_get_fdtable();

	struct _net_socket *s = sock_table->sockfds[sockid];
	sock_table->sockfds[sockid] = NULL;

	pthread_spin_lock(&sock_table->lock);

	char byte = net_socket_unuse_id(sock_table->open_fds, sockid);

	sock_table->cur_idx = net_socket_set_start(sockid);
	net_trace_socket("net_socket_free --> net_socket_unuse_id : %x, %d\n",
		byte, sock_table->cur_idx);
	
	pthread_spin_unlock(&sock_table->lock);

	free(s);

	UNUSED(byte);
	net_trace_socket("net_socket_free --> Exit\n");

	return ;
}

// 根据套接字 ID 获取套接字
struct _net_socket* net_socket_get(int sockid) {

	struct _net_socket_table *sock_table = net_socket_get_fdtable();
	if(sock_table == NULL) return NULL;

	return sock_table->sockfds[sockid];
}

// 关闭指定的流
int net_socket_close_stream(int sockid) {
	
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	struct _net_socket *s = net_socket_get(sockid);
	if (s == NULL) return -1;

	// 获取当前流
	net_tcp_stream *cur_stream = s->stream;
	if (!cur_stream) {
		net_trace_api("Socket %d: stream does not exist.\n", sockid);
		errno = ENOTCONN;
		return -1;
	}

	if (cur_stream->closed) {
		net_trace_api("Socket %d (Stream %u): already closed stream\n", 
				sockid, cur_stream->id);
		return 0;
	}
	cur_stream->closed = 1;
	
	net_trace_api("Stream %d: closing the stream.\n", cur_stream->id);
	cur_stream->s = NULL;

	// 根据流的状态进行处理
	if (cur_stream->state == NET_TCP_CLOSED) {
		// 如果流的状态是 TCP_CLOSED，销毁流
		printf("Stream %d at TCP_ST_CLOSED. destroying the stream.\n", 
				cur_stream->id);
		
		StreamEnqueue(tcp->destroyq, cur_stream);
		tcp->wakeup_flag = 1;
		
		return 0;
	} else if (cur_stream->state == NET_TCP_SYN_SENT) {
		// 如果流的状态是 TCP_SYN_SENT，也将流放入销毁队列
		StreamEnqueue(tcp->destroyq, cur_stream);		
		tcp->wakeup_flag = 1;
		//流的状态不符合关闭要求
		return -1;
	} else if (cur_stream->state != NET_TCP_ESTABLISHED &&
			   cur_stream->state != NET_TCP_CLOSE_WAIT) {
		//既不是 TCP_ESTABLISHED 也不是 TCP_CLOSE_WAIT
		//出错 无效的描述符
		net_trace_api("Stream %d at state %d\n", 
				cur_stream->id, cur_stream->state);
		errno = -EBADF;
		return -1;
	}

    // 如果流的状态是 TCP_ESTABLISHED 或 TCP_CLOSE_WAIT
    // 将流标记为需要关闭，并放入关闭队列

	cur_stream->snd->on_closeq = 1;
	int ret = StreamEnqueue(tcp->closeq, cur_stream);
	tcp->wakeup_flag = 1;

	if (ret < 0) {
		net_trace_api("(NEVER HAPPEN) Failed to enqueue the stream to close.\n");
		errno = EAGAIN;
		return -1;
	}

	return 0;
}

int net_socket_close_listening(int sockid) {

	// 获取 TCP 管理器
	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	// 获取指定 ID 的套接字
	struct _net_socket *s = net_socket_get(sockid);
	if (s == NULL) return -1;
	
	// 获取套接字对应的 TCP 监听器
	struct _net_tcp_listener *listener = s->listener;
	if (!listener) {
		errno = EINVAL;
		return -1;
	}

	// 如果监听器的接收队列存在，销毁该队列
	if (listener->acceptq) {
		DestroyStreamQueue(listener->acceptq);
		listener->acceptq = NULL;
	}

	// 锁定监听器的互斥锁，发送信号唤醒等待线程，然后解锁
	// 将等待条件变量的线程唤醒以免永久阻塞
	pthread_mutex_lock(&listener->accept_lock);
	pthread_cond_signal(&listener->accept_cond);
	pthread_mutex_unlock(&listener->accept_lock);

	// 销毁条件变量和互斥锁
	pthread_cond_destroy(&listener->accept_cond);
	pthread_mutex_destroy(&listener->accept_lock);

	free(listener);
	s->listener = NULL;

	return 0;
}


#endif

