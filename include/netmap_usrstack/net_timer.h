#ifndef __NET_TIMER_H__
#define __NET_TIMER_H__

#include "netmap_usrstack/net_tcp.h"
#include "netmap_usrstack/net_queue.h"

#include <stdint.h>

// RTO 哈希表
#define RTO_HASH		3000

typedef struct _net_rto_hashstore {
	uint32_t rto_now_idx; // 当前的 RTO 索引
	uint32_t rto_now_ts; // 当前时间戳（毫秒级）

    // 定义一个链表数组，每个链表用于存储 TCP 流（_net_tcp_stream 类型的实例）
    // 数组的大小为 RTO_HASH + 1，以确保链表能够处理冲突
	TAILQ_HEAD(rto_head, _net_tcp_stream) rto_list[RTO_HASH+1];
} net_rto_hashstore;

net_rto_hashstore *InitRTOHashstore(void);

#endif

