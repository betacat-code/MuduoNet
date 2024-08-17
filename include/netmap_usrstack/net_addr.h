#ifndef __NET_ADDR_H__
#define __NET_ADDR_H__
//管理网络地址和端口的分配
#include "netmap_usrstack/net_queue.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <netinet/in.h>


//端口范围
#define NET_MIN_PORT			1025
#define NET_MAX_PORT			65535

#ifndef INPORT_ANY
#define INPORT_ANY 	(uint16_t)0
#endif

//网络地址 存储网络地址和该entry在链表中的链接
typedef struct _net_addr_entry {
	struct sockaddr_in addr;
	TAILQ_ENTRY(_net_addr_entry) addr_link;
} net_addr_entry;

//映射端口到entry
typedef struct _net_addr_map {
	net_addr_entry *addrmap[NET_MAX_PORT]; 
} net_addr_map;

//网络地址池
typedef struct _net_addr_pool {
	net_addr_entry *pool;
	net_addr_map *mapper;

	uint32_t addr_base;

	int num_addr;
	int num_entry;
	int num_free;
	int num_used;

	pthread_mutex_t lock;
	TAILQ_HEAD(, _net_addr_entry) free_list;
	TAILQ_HEAD(, _net_addr_entry) used_list;
} net_addr_pool;


net_addr_pool *CreateAddressPool(in_addr_t addr_base, int num_addr);
net_addr_pool *CreateAddressPoolPerCore(int core, int num_queues, 
		in_addr_t saddr_base, int num_addr, in_addr_t daddr, in_port_t dport);

void DestroyAddressPool(net_addr_pool *ap);

//用于从地址池中获取地址
int FetchAddress(net_addr_pool *ap, int core, int num_queues, 
		const struct sockaddr_in *daddr, struct sockaddr_in *saddr);

int FetchAddressPerCore(net_addr_pool *ap, int core, int num_queues,
		    const struct sockaddr_in *daddr, struct sockaddr_in *saddr);

int FreeAddress(net_addr_pool *ap, const struct sockaddr_in *addr);

//根据源地址、目的地址、端口等信息获取 RSS（接收负载均衡）CPU 核心
int GetRSSCPUCore(in_addr_t sip, in_addr_t dip, 
	      in_port_t sp, in_port_t dp, int num_queues, uint8_t endian_check);


#endif


