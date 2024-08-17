#ifndef __NET_BUFFER_H__
#define __NET_BUFFER_H__

//网络缓冲区

#include <stdint.h>
#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <bits/types.h>
#include <errno.h>
#include <uchar.h>

#include "netmap_usrstack/net_queue.h"
#include "netmap_usrstack/net_tree.h"
#include "netmap_usrstack/net_mempool.h"


enum rb_caller
{
	AT_APP, 
	AT_MTCP
};


#define MAX(a, b) ((a)>(b)?(a):(b))
#define MIN(a, b) ((a)<(b)?(a):(b))
#define NextIndex(sq, i)	(i != sq->_capacity ? i + 1: 0)
#define PrevIndex(sq, i)	(i != 0 ? i - 1: sq->_capacity)
#define MemoryBarrier(buf, idx)	__asm__ volatile("" : : "m" (buf), "m" (idx))

//管理发送缓冲区
typedef struct _net_sb_manager
{
	size_t chunk_size;
	uint32_t cur_num;
	uint32_t cnum;
	struct _net_mempool *mp;
	struct _net_sb_queue *freeq;

} net_sb_manager;

//发送缓冲区
typedef struct _net_send_buffer {
	unsigned char *data;
	unsigned char *head;

	uint32_t head_off;
	uint32_t tail_off;
	uint32_t len;
	uint64_t cum_len;
	uint32_t size;

	uint32_t head_seq;
	uint32_t init_seq;
} net_send_buffer;

#ifndef _INDEX_TYPE_
#define _INDEX_TYPE_
typedef uint32_t index_type;
typedef int32_t signed_index_type;
#endif

//环形缓冲区队列
typedef struct _net_sb_queue {
	index_type _capacity;
	volatile index_type _head;
	volatile index_type _tail;

	net_send_buffer * volatile * _q;
} net_sb_queue;



//与net_sb_queue类似，不过管理片段上下文
typedef struct _net_rb_frag_queue {
	index_type _capacity;
	volatile index_type _head;
	volatile index_type _tail;

	struct _net_fragment_ctx * volatile * _q;
} net_rb_frag_queue;


//环形缓冲区中的一个数据片段

typedef struct _net_fragment_ctx {
	uint32_t seq;
	uint32_t len:31,
			 is_calloc:1;
	struct _net_fragment_ctx *next;
} net_fragment_ctx;

//处理实际的数据缓冲区 其中数据片段是net_fragment_ctx
typedef struct _net_ring_buffer {
	u_char *data;
	u_char *head;

	uint32_t head_offset;
	uint32_t tail_offset;

	int merged_len;
	uint64_t cum_len;
	int last_len;
	int size;

	uint32_t head_seq;
	uint32_t init_seq;

	net_fragment_ctx *fctx;
} net_ring_buffer;

//管理环形缓冲区和片段的分配
typedef struct _net_rb_manager {
	size_t chunk_size;
	uint32_t cur_num;
	uint32_t cnum;

	net_mempool *mp;
	net_mempool *frag_mp;

	net_rb_frag_queue *free_fragq;
	net_rb_frag_queue *free_fragq_int;
	
} net_rb_manager;


//处理流的存取
typedef struct _net_stream_queue
{
	index_type _capacity;
	volatile index_type _head;
	volatile index_type _tail;

	struct _net_tcp_stream * volatile * _q;
} net_stream_queue;

typedef struct _net_stream_queue_int
{
	struct _net_tcp_stream **array;
	int size;

	int first;
	int last;
	int count;

} net_stream_queue_int;

//初始化发送缓冲区和环形缓冲区
net_sb_manager *net_sbmanager_create(size_t chunk_size, uint32_t cnum);
net_rb_manager *RBManagerCreate(size_t chunk_size, uint32_t cnum);

//管理网络流队列
net_stream_queue *CreateStreamQueue(int capacity);
net_stream_queue_int *CreateInternalStreamQueue(int size);
void DestroyInternalStreamQueue(net_stream_queue_int *sq);

//发送缓冲区
net_send_buffer *SBInit(net_sb_manager *sbm, uint32_t init_seq);
void SBFree(net_sb_manager *sbm, net_send_buffer *buf);
size_t SBPut(net_sb_manager *sbm, net_send_buffer *buf, const void *data, size_t len);
int SBEnqueue(net_sb_queue *sq, net_send_buffer *buf);
size_t SBRemove(net_sb_manager *sbm, net_send_buffer *buf, size_t len);

//环形缓冲区操作
size_t RBRemove(net_rb_manager *rbm, net_ring_buffer* buff, size_t len, int option);
int RBPut(net_rb_manager *rbm, net_ring_buffer* buff, 
	   void* data, uint32_t len, uint32_t cur_seq);
void RBFree(net_rb_manager *rbm, net_ring_buffer* buff);

//流队列操作
int StreamInternalEnqueue(net_stream_queue_int *sq, struct _net_tcp_stream *stream);
struct _net_tcp_stream *StreamInternalDequeue(net_stream_queue_int *sq);

net_sb_queue *CreateSBQueue(int capacity);
int StreamQueueIsEmpty(net_stream_queue *sq);

net_send_buffer *SBDequeue(net_sb_queue *sq);

net_ring_buffer *RBInit(net_rb_manager *rbm, uint32_t init_seq);

struct _net_tcp_stream *StreamDequeue(net_stream_queue *sq);
int StreamEnqueue(net_stream_queue *sq, struct _net_tcp_stream *stream);

void DestroyStreamQueue(net_stream_queue *sq);

#endif



