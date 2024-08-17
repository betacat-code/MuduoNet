#include "netmap_usrstack/net_tree.h"
#include "netmap_usrstack/net_queue.h"
#include "netmap_usrstack/net_epoll_inner.h"
#include "netmap_usrstack/net_config.h"

#if NET_ENABLE_EPOLL_RB

#include <pthread.h>
#include <stdint.h>
#include <time.h>

extern net_tcp_manager *net_get_tcp_manager(void);

int epoll_create(int size) {

	if (size <= 0) return -1;

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	// 分配一个新的网络套接字用于 epoll
	struct _net_socket *epsocket = net_socket_allocate(NET_TCP_SOCK_EPOLL);
	if (epsocket == NULL) {
		net_trace_epoll("malloc failed\n");
		return -1;
	}

    // 为 eventpoll 结构体分配内存
	struct eventpoll *ep = (struct eventpoll*)calloc(1, sizeof(struct eventpoll));
	if (!ep) {
		net_free_socket(epsocket->id, 0);
		return -1;
	}

    // 初始化红黑树   就绪队列
	ep->rbcnt = 0;
	RB_INIT(&ep->rbr);
	LIST_INIT(&ep->rdlist);

	// 初始化互斥锁 初始化失败需要释放申请的所有资源
	if (pthread_mutex_init(&ep->mtx, NULL)) {
		free(ep);
		net_free_socket(epsocket->id, 0);
		return -2;
	}

	if (pthread_mutex_init(&ep->cdmtx, NULL)) {
		pthread_mutex_destroy(&ep->mtx);
		free(ep);
		net_free_socket(epsocket->id, 0);
		return -2;
	}

	if (pthread_cond_init(&ep->cond, NULL)) {
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		free(ep);
		net_free_socket(epsocket->id, 0);
		return -2;
	}

	if (pthread_spin_init(&ep->lock, PTHREAD_PROCESS_SHARED)) {
		pthread_cond_destroy(&ep->cond);
		pthread_mutex_destroy(&ep->cdmtx);
		pthread_mutex_destroy(&ep->mtx);
		free(ep);

		net_free_socket(epsocket->id, 0);
		return -2;
	}

	// 将新创建的 eventpoll 结构体指针保存到 TCP 管理器和套接字中
	tcp->ep = (void*)ep;
	epsocket->ep = (void*)ep;

	return epsocket->id;
}

// 对rb_tree上的节点, 进行[增删改]操作
int epoll_ctl(int epid, int op, int sockid, struct epoll_event *event) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;
	
	// 获取与 epid 对应的 socket
	struct _net_socket *epsocket = tcp->fdtable->sockfds[epid];
	
	// 检查 socket 是否有效
	if (epsocket->socktype == NET_TCP_SOCK_UNUSED) {
		errno = -EBADF;
		return -1;
	}

	// 检查 socket 类型
	if (epsocket->socktype != NET_TCP_SOCK_EPOLL) {
		errno = -EINVAL;
		return -1;
	}

	net_trace_epoll(" epoll_ctl --> eventpoll\n");

	struct eventpoll *ep = (struct eventpoll*)epsocket->ep;

	//为空 无效事件 如果是删除或修改必须有event
	if (!ep || (!event && op != EPOLL_CTL_DEL)) {
		errno = -EINVAL;
		return -1;
	}

	// 增加事件
	if (op == EPOLL_CTL_ADD) {

		pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;

		// 查找与 sockid 对应的 epitem 有直接返回异常
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) {
			net_trace_epoll("rbtree is exist\n");
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		// 分配内存用于新的 epitem
		epi = (struct epitem*)calloc(1, sizeof(struct epitem));
		if (!epi) {
			pthread_mutex_unlock(&ep->mtx);
			errno = -ENOMEM;
			return -1;
		}
		
		epi->sockfd = sockid;
		memcpy(&epi->event, event, sizeof(struct epoll_event));

		// 将新的 epitem 插入红黑树
		epi = RB_INSERT(_epoll_rb_socket, &ep->rbr, epi);
		assert(epi == NULL);
		ep->rbcnt ++;
		
		pthread_mutex_unlock(&ep->mtx);

	} 
	// 删除事件
	else if (op == EPOLL_CTL_DEL) {

		pthread_mutex_lock(&ep->mtx);

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (!epi) {
			net_trace_epoll("rbtree no exist\n");
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}
		
		// 从红黑树中移除 epitem
		epi = RB_REMOVE(_epoll_rb_socket, &ep->rbr, epi);
		if (!epi) {
			net_trace_epoll("rbtree is no exist\n");
			pthread_mutex_unlock(&ep->mtx);
			return -1;
		}

		ep->rbcnt --;
		free(epi);
		
		pthread_mutex_unlock(&ep->mtx);

	} 
	// 修改事件
    else if (op == EPOLL_CTL_MOD) {

		struct epitem tmp;
		tmp.sockfd = sockid;
		struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
		if (epi) {
			epi->event.events = event->events;
			// 必须包含错误和挂起事件
			epi->event.events |= EPOLLERR | EPOLLHUP;
		} else {
			errno = -ENOENT;
			return -1;
		}

	} else {
		net_trace_epoll("op is no exist\n");
		assert(0);
	}

	return 0;
}

// 等待cond条件的到来
// cond条件到来后, 把就绪队列中的数据, 拷贝到用户空间events
int epoll_wait(int epid, struct epoll_event *events, int maxevents, int timeout) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	//net_socket_map *epsocket = &tcp->smap[epid];
	struct _net_socket *epsocket = tcp->fdtable->sockfds[epid];
	if (epsocket == NULL) return -1;

	if (epsocket->socktype == NET_TCP_SOCK_UNUSED) {
		errno = -EBADF;
		return -1;
	}

	if (epsocket->socktype != NET_TCP_SOCK_EPOLL) {
		errno = -EINVAL;
		return -1;
	}

	struct eventpoll *ep = (struct eventpoll*)epsocket->ep;
	if (!ep || !events || maxevents <= 0) {
		errno = -EINVAL;
		return -1;
	}

	// 尝试锁定互斥锁以访问事件队列
	if (pthread_mutex_lock(&ep->cdmtx)) {
		if (errno == EDEADLK) {
			net_trace_epoll("epoll lock blocked\n");
		}
		assert(0);
	}

	// 当没有就绪事件且超时未到时，等待事件的到来
	while (ep->rdnum == 0 && timeout != 0) {

		ep->waiting = 1;
		if (timeout > 0) {
			struct timespec deadline;
			// 计算超时的绝对截止时间
			clock_gettime(CLOCK_REALTIME, &deadline);
			if (timeout >= 1000) {
				int sec;
				sec = timeout / 1000;
				deadline.tv_sec += sec;
				timeout -= sec * 1000;
			}

			deadline.tv_nsec += timeout * 1000000;

			if (deadline.tv_nsec >= 1000000000) {
				deadline.tv_sec++;
				deadline.tv_nsec -= 1000000000;
			}

            // 等待cond条件变量 (条件到来后, 就绪队列中已经有就绪事件了)
			int ret = pthread_cond_timedwait(&ep->cond, &ep->cdmtx, &deadline);
			if (ret && ret != ETIMEDOUT) {

				net_trace_epoll("pthread_cond_timewait\n");
				pthread_mutex_unlock(&ep->cdmtx);
				return -1;
			}
			timeout = 0;// 超时值设为0，表明超时已经处理
		} 
		else if (timeout < 0) {
			// 无限等待条件变量
			int ret = pthread_cond_wait(&ep->cond, &ep->cdmtx);
			if (ret) {
				net_trace_epoll("pthread_cond_wait\n");
				pthread_mutex_unlock(&ep->cdmtx);

				return -1;
			}
		}
		ep->waiting = 0; 

	}

	pthread_mutex_unlock(&ep->cdmtx);

	// 加锁访问就绪事件列表 
	pthread_spin_lock(&ep->lock);

	int cnt = 0;
	int num = (ep->rdnum > maxevents ? maxevents : ep->rdnum);
	int i = 0;

    // 将就绪事件从就绪队列拷贝到用户提供的events数组中
	while (num != 0 && !LIST_EMPTY(&ep->rdlist)) {

		 // 获取队列中的第一个事件
        struct epitem *epi = LIST_FIRST(&ep->rdlist);

        LIST_REMOVE(epi, rdlink);  // 从队列中移除事件
        epi->rdy = 0;  // 重置事件的就绪标志

		memcpy(&events[i++], &epi->event, sizeof(struct epoll_event));
		
		num --;
		cnt ++;
		ep->rdnum --;
	}
	
	pthread_spin_unlock(&ep->lock);

	return cnt;
}


// 通过sockid在红黑树上找到节点epi, 将该节点epi添加到就绪队列中
int epoll_event_callback(struct eventpoll *ep, int sockid, uint32_t event) {

	struct epitem tmp;
	tmp.sockfd = sockid;

    // 通过sockid, 在红黑树中找到节点epi
	struct epitem *epi = RB_FIND(_epoll_rb_socket, &ep->rbr, &tmp);
	if (!epi) {
		net_trace_epoll("rbtree not exist\n");
		assert(0);
	}
	if (epi->rdy) {
		epi->event.events |= event;
		return 1;
	} 

	net_trace_epoll("epoll_event_callback --> %d\n", epi->sockfd);

    // 将epi节点, 插入到就绪队列
	pthread_spin_lock(&ep->lock);
	epi->rdy = 1;
	LIST_INSERT_HEAD(&ep->rdlist, epi, rdlink);
	ep->rdnum ++;
	pthread_spin_unlock(&ep->lock);

	pthread_mutex_lock(&ep->cdmtx);

    // 唤醒epoll_wait上等待的条件变量
	pthread_cond_signal(&ep->cond);
	pthread_mutex_unlock(&ep->cdmtx);
	return 0;
}

//销毁 eventpoll 结构体中的所有事件
static int epoll_destroy(struct eventpoll *ep) {


	while (!LIST_EMPTY(&ep->rdlist)) {
		struct epitem *epi = LIST_FIRST(&ep->rdlist);
		LIST_REMOVE(epi, rdlink);
	}
	
	pthread_mutex_lock(&ep->mtx);
	
	for (;;) {
		struct epitem *epi = RB_MIN(_epoll_rb_socket, &ep->rbr);
		if (epi == NULL) break;
		
		epi = RB_REMOVE(_epoll_rb_socket, &ep->rbr, epi);
		free(epi);
	}
	pthread_mutex_unlock(&ep->mtx);

	return 0;
}

//关闭一个 epoll 实例
int net_epoll_close_socket(int epid) {

	net_tcp_manager *tcp = net_get_tcp_manager();
	if (!tcp) return -1;

	struct eventpoll *ep = (struct eventpoll *)tcp->fdtable->sockfds[epid]->ep;
	if (!ep) {
		errno = -EINVAL;
		return -1;
	}

	epoll_destroy(ep);

	pthread_mutex_lock(&ep->mtx);
	tcp->ep = NULL;
	tcp->fdtable->sockfds[epid]->ep = NULL;
	pthread_cond_signal(&ep->cond);
	pthread_mutex_unlock(&ep->mtx);

	pthread_cond_destroy(&ep->cond);
	pthread_mutex_destroy(&ep->mtx);

	pthread_spin_destroy(&ep->lock);

	free(ep);

	return 0;
}


#endif


