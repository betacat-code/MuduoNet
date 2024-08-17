#include "netmap_usrstack/net_hash.h"
#include "netmap_usrstack/net_tcp.h"

//使用流的地址信息来生成哈希值，从而在哈希表中定位流
unsigned int HashFlow(const void *f) {
	net_tcp_stream *flow = (net_tcp_stream*)f;

	unsigned int hash, i;
	char *key = (char *)&flow->saddr;

	for (hash = i = 0;i < 12;i ++) {
		hash += key[i];
		hash += (hash << 10);
		hash ^= (hash >> 6);
	}
	hash += (hash << 3);
	hash ^= (hash >> 11);
	hash += (hash << 15);

	return hash & (NUM_BINS_FLOWS-1);
}

//用于比较两个 net_tcp_stream 结构体是否相等
inline int EqualFlow(const void *f1, const void *f2) {
	net_tcp_stream *flow1 = (net_tcp_stream*)f1;
	net_tcp_stream *flow2 = (net_tcp_stream*)f2;

	return (flow1->saddr == flow2->saddr &&
			flow1->sport == flow2->sport &&
		    flow1->daddr == flow2->daddr &&
		    flow1->dport == flow2->dport);
}

//使用监听器的端口号计算哈希值
unsigned int HashListener(const void *l) {
	net_tcp_listener *listener = (net_tcp_listener*)l;

	return listener->s->s_addr.sin_port & (NUM_BINS_LISTENERS - 1);
}

int EqualListener(const void *l1, const void *l2) {
	net_tcp_listener *listener1 = (net_tcp_listener*)l1;
	net_tcp_listener *listener2 = (net_tcp_listener*)l2;

	return (listener1->s->s_addr.sin_port == listener2->s->s_addr.sin_port);
}


#define IS_FLOW_TABLE(x) 	(x == HashFlow)
#define IS_LISTEN_TABLE(x)	(x == HashListener)


net_hashtable *CreateHashtable(unsigned int (*hashfn) (const void *), // key function
		int (*eqfn) (const void*, const void *),            // equality
		int bins) // 桶的数量
{
	int i;
	net_hashtable* ht = calloc(1, sizeof(net_hashtable));
	if (!ht){
		printf("calloc: CreateHashtable");
		return 0;
	}

	ht->hashfn = hashfn;
	ht->eqfn = eqfn;
	ht->bins = bins;

	//// 根据哈希函数的类型创建桶
	if (IS_FLOW_TABLE(hashfn)) {
		ht->ht_stream = calloc(bins, sizeof(hash_bucket_head));
		//如果分配失败，打印错误信息并释放已分配的内存
		if (!ht->ht_stream) {
			printf("calloc: CreateHashtable bins!\n");
			free(ht);
			return 0;
		}
		for (i = 0; i < bins; i++)
			TAILQ_INIT(&ht->ht_stream[i]);
	} else if (IS_LISTEN_TABLE(hashfn)) {
		ht->ht_listener = calloc(bins, sizeof(list_bucket_head));
		if (!ht->ht_listener) {
			printf("calloc: CreateHashtable bins!\n");
			free(ht);
			return 0;
		}
		for (i = 0; i < bins; i++)
			TAILQ_INIT(&ht->ht_listener[i]);
	}

	return ht;
}


void DestroyHashtable(net_hashtable *ht) {
	if (IS_FLOW_TABLE(ht->hashfn)) {
		free(ht->ht_stream);
	} else {
		free(ht->ht_listener);
	}
	free(ht);
}

//流的插入 删除 查询
int StreamHTInsert(net_hashtable *ht, void *it)
{ 
	int idx;
	net_tcp_stream *item = (net_tcp_stream*)it;

	assert(ht);
	
	idx = ht->hashfn(item);
	assert(idx >=0 && idx < NUM_BINS_FLOWS);

	TAILQ_INSERT_TAIL(&ht->ht_stream[idx], item, rcv->he_link);

	item->ht_idx = TCP_AR_CNT;
	ht->ht_count++;
	
	return 0;
}


void *StreamHTRemove(net_hashtable *ht, void *it)
{
	hash_bucket_head *head;
	struct _net_tcp_stream *item = (struct _net_tcp_stream *)it;
	int idx = ht->hashfn(item);

	head = &ht->ht_stream[idx];
	TAILQ_REMOVE(head, item, rcv->he_link);	

	ht->ht_count--;
	return (item);
}	


void *StreamHTSearch(net_hashtable *ht, const void *it)
{
	int idx;
	const net_tcp_stream *item = (const net_tcp_stream *)it;
	net_tcp_stream *walk;
	hash_bucket_head *head;

	idx = ht->hashfn(item);

	head = &ht->ht_stream[idx];
	TAILQ_FOREACH(walk, head, rcv->he_link) {
		if (ht->eqfn(walk, item)) 
			return walk;
	}

	return NULL;
}

//监听器的插入 删除 查询
int ListenerHTInsert(net_hashtable *ht, void *it)
{
	int idx;
	struct _net_tcp_listener *item = (struct _net_tcp_listener *)it;

	assert(ht);
	
	idx = ht->hashfn(item);
	assert(idx >=0 && idx < NUM_BINS_LISTENERS);

	TAILQ_INSERT_TAIL(&ht->ht_listener[idx], item, he_link);
	ht->ht_count++;
	
	return 0;
}


void * ListenerHTRemove(net_hashtable *ht, void *it)
{
	list_bucket_head *head;
	struct _net_tcp_listener *item = (struct _net_tcp_listener *)it;
	int idx = ht->hashfn(item);

	head = &ht->ht_listener[idx];
	TAILQ_REMOVE(head, item, he_link);	

	ht->ht_count--;
	return (item);
}	

void * ListenerHTSearch(net_hashtable *ht, const void *it)
{
	int idx;
	net_tcp_listener item;
	uint16_t port = *((uint16_t *)it);
	net_tcp_listener *walk;
	list_bucket_head *head;

	struct _net_socket s;

	s.s_addr.sin_port = port;
	item.s = &s;

	idx = ht->hashfn(&item);

	head = &ht->ht_listener[idx];
	TAILQ_FOREACH(walk, head, he_link) {
		if (ht->eqfn(walk, &item)) 
			return walk;
	}

	return NULL;
}





