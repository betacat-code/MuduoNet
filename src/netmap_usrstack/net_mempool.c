#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <sys/mman.h>

//sudo apt-get install libhugetlbfs-dev
#include <hugetlbfs.h>

#include "netmap_usrstack/net_mempool.h"

net_mempool *net_mempool_create(int chunk_size, size_t total_size, int is_hugepage) {

	if (chunk_size < (int)sizeof(net_mem_chunk)) {
		return NULL;
	}
	if (chunk_size % 4 != 0) {
		printf("net_mempool_create --> chunk_size: %d\n", chunk_size);
		return NULL;
	}

	net_mempool *mp = calloc(1, sizeof(net_mempool));
	if (mp == NULL) { 
		printf("net_mempool_create --> calloc failed\n");
		return NULL;
	}

	mp->mp_type = is_hugepage;
	mp->mp_chunk_size = chunk_size;
	mp->mp_free_chunks = (total_size + (chunk_size-1)) / chunk_size;
	mp->mp_total_chunks = mp->mp_free_chunks;
    
    //大页优化
	if (is_hugepage == MEM_HUGEPAGE) {
		mp->mp_startptr = get_huge_pages(total_size, GHP_DEFAULT);
		if (!mp->mp_startptr) {
			free(mp);
			assert(0);
		}
	} else {
		int res = posix_memalign((void **)&mp->mp_startptr, getpagesize(), total_size);
		if (res != 0) {
			free(mp);
			assert(0);
		}
	}

	if (geteuid() == 0) {
		if (mlock(mp->mp_startptr, total_size) < 0) {
			
		}
	}

	mp->mp_freeptr = (net_mem_chunk *)mp->mp_startptr;
	mp->mp_freeptr->mc_free_chunks = mp->mp_free_chunks;
	mp->mp_freeptr->next = NULL;

	return mp;
}

//分配一个内存块
void net_mempool_destory(net_mempool *mp) {
	if (mp->mp_type == MEM_HUGEPAGE) {
		free_huge_pages(mp->mp_startptr);
	} else {
		free(mp->mp_startptr);
	}

	free(mp);
}

void *net_mempool_alloc(net_mempool *mp) {

	net_mem_chunk *p = mp->mp_freeptr;

	if (mp->mp_free_chunks == 0) return NULL;

	assert(p->mc_free_chunks > 0);

	p->mc_free_chunks --;
	mp->mp_free_chunks --;

	if (p->mc_free_chunks) {
		mp->mp_freeptr = (net_mem_chunk*)((u_char*)p + mp->mp_chunk_size);
		mp->mp_freeptr->mc_free_chunks = p->mc_free_chunks;
		mp->mp_freeptr->next = p->next;
	} else {
		mp->mp_freeptr = p->next;
	}

	return p;
}


void net_mempool_free(net_mempool *mp, void *p) {
	net_mem_chunk *mcp = (net_mem_chunk*)p;

	assert(((u_char*)p - mp->mp_startptr) % mp->mp_chunk_size == 0);

	mcp->mc_free_chunks = 1;
	mcp->next = mp->mp_freeptr;
	mp->mp_freeptr = mcp;
	mp->mp_free_chunks ++;
}

//获取当前内存池中的空闲内存块数量
int net_mempool_getfree_chunks(net_mempool *mp) {
	return mp->mp_free_chunks;
}

uint32_t net_mempool_isdanger(net_mempool *mp) {
#define DANGER_THREADSHOLD	0.95
#define SAFE_THREADSHOLD	0.90

	uint32_t danger_num = mp->mp_total_chunks * DANGER_THREADSHOLD;
	uint32_t safe_num = mp->mp_total_chunks * SAFE_THREADSHOLD;

	if ((int)danger_num < mp->mp_total_chunks - mp->mp_free_chunks) {
		return mp->mp_total_chunks - mp->mp_free_chunks - safe_num;
	}
	return 0;
}



