
#ifndef __NET_HASH_H__
#define __NET_HASH_H__


#include <stdint.h>

#include "netmap_usrstack/net_queue.h"
//#include "net_tcp.h"


#define NUM_BINS_FLOWS		131072 //流的哈希表
#define NUM_BINS_LISTENERS	1024 //监听器的哈希表
#define TCP_AR_CNT			3

//分别用于 TCP 流和监听器

#define HASH_BUCKET_ENTRY(type)	\
	struct {					\
		struct type *tqh_first;	\
		struct type **tqh_last;	\
	}


typedef HASH_BUCKET_ENTRY(_net_tcp_stream) hash_bucket_head;
typedef HASH_BUCKET_ENTRY(_net_tcp_listener) list_bucket_head;

//链地址法解决冲突
typedef struct _net_hashtable {
	uint8_t ht_count;
	uint32_t bins;
	union {
		hash_bucket_head *ht_stream;
		list_bucket_head *ht_listener;
	};
	unsigned int (*hashfn)(const void *);
	int (*eqfn)(const void *, const void *);
} net_hashtable;

//搜索监听器和流在哈希表中的位置
void *ListenerHTSearch(net_hashtable *ht, const void *it);
void *StreamHTSearch(net_hashtable *ht, const void *it);

//将监听器和流插入哈希表
int ListenerHTInsert(net_hashtable *ht, void *it);
int StreamHTInsert(net_hashtable *ht, void *it);

//从哈希表中移除流
void *StreamHTRemove(net_hashtable *ht, void *it);

//流的哈希值计算和比较
unsigned int HashFlow(const void *f);
int EqualFlow(const void *f1, const void *f2);

//监听器的哈希值计算和比较
unsigned int HashListener(const void *l);
int EqualListener(const void *l1, const void *l2);

//创建和销毁哈希表
net_hashtable *CreateHashtable(unsigned int (*hashfn) (const void *), // key function
		int (*eqfn) (const void*, const void *),            // equality
		int bins);
void DestroyHashtable(net_hashtable *ht);

#endif


