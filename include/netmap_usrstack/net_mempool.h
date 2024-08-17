#ifndef __NET_MEMPOOL_H__
#define __NET_MEMPOOL_H__


//普通内存和大页内存
enum {
	MEM_NORMAL,
	MEM_HUGEPAGE
};

//内存块
typedef struct _net_mem_chunk {
	int mc_free_chunks;
	struct _net_mem_chunk *next;
} net_mem_chunk;

//内存池
typedef struct _net_mempool {
	u_char *mp_startptr;
	net_mem_chunk *mp_freeptr;
	int mp_free_chunks;
	int mp_total_chunks;
	int mp_chunk_size;
	int mp_type;
} net_mempool;


net_mempool *net_mempool_create(int chunk_size, size_t total_size, int is_hugepage);

void net_mempool_destory(net_mempool *mp);

void *net_mempool_alloc(net_mempool *mp);

void net_mempool_free(net_mempool *mp, void *p);


#endif



