#include "netmap_usrstack/net_buffer.h"

//初始化发送缓存管理器 
net_sb_manager *net_sbmanager_create(size_t chunk_size, uint32_t cnum)
{
	net_sb_manager *sbm = (net_sb_manager *)calloc(1, sizeof(net_sb_manager));
	if (!sbm) {
		printf("SBManagerCreate() failed. %s\n", strerror(errno));
		return NULL;
	}

	sbm->chunk_size = chunk_size;
	sbm->cnum = cnum;
	sbm->mp = (struct _net_mempool*)net_mempool_create(chunk_size, (uint64_t)chunk_size * cnum, 0);
	if (!sbm->mp) {
		printf("Failed to create mem pool for sb.\n");
		free(sbm);
		return NULL;
	}

	sbm->freeq = CreateSBQueue(cnum);
	if (!sbm->freeq) {
		printf("Failed to create free buffer queue.\n");
		net_mempool_destory(sbm->mp);
		free(sbm);
		return NULL;
	}

	return sbm;
}

//初始化 net_send_buffer 实例
net_send_buffer *SBInit(net_sb_manager *sbm, uint32_t init_seq)
{
	net_send_buffer *buf;

	// 从先空闲缓冲区队列中获取一个缓冲区
	buf = SBDequeue(sbm->freeq);
	if (!buf) {
		buf = (net_send_buffer *)malloc(sizeof(net_send_buffer));
		if (!buf) {
			perror("malloc() for buf");
			return NULL;
		}
		buf->data = net_mempool_alloc(sbm->mp);
		if (!buf->data) {
			printf("Failed to fetch memory chunk for data.\n");
			free(buf);
			return NULL;
		}
		sbm->cur_num++;
	}

	buf->head = buf->data;

	buf->head_off = buf->tail_off = 0;
	buf->len = buf->cum_len = 0;
	buf->size = sbm->chunk_size;

	buf->init_seq = buf->head_seq = init_seq;
	
	return buf;
}

//释放一个发送缓存，将其重新放回空闲缓冲区队列
void SBFree(net_sb_manager *sbm, net_send_buffer *buf)
{
	if (!buf)
		return;

	SBEnqueue(sbm->freeq, buf);
}

//将数据放入 缓存区中
size_t SBPut(net_sb_manager *sbm, net_send_buffer *buf, const void *data, size_t len)
{
	size_t to_put;

	if (len <= 0)
		return 0;

	// 计算可以放入缓冲区的数据长度 无空间返回2
	to_put = MIN(len, buf->size - buf->len);
	if (to_put <= 0) {
		return -2;
	}

	if (buf->tail_off + to_put < buf->size) {
		// 如果数据能够放入缓冲区，则直接复制
		memcpy(buf->data + buf->tail_off, data, to_put);
		buf->tail_off += to_put;
	} else {
		// 如果缓冲区溢出，则移动现有数据并合并
		memmove(buf->data, buf->head, buf->len);
		buf->head = buf->data;
		buf->head_off = 0;
		memcpy(buf->head + buf->len, data, to_put);
		buf->tail_off = buf->len + to_put;
	}
	buf->len += to_put;
	buf->cum_len += to_put;

	return to_put;
}

size_t SBRemove(net_sb_manager *sbm, net_send_buffer *buf, size_t len)
{
	size_t to_remove;

	if (len <= 0){
		return 0;
	}

    // 如果计算出的要移除的长度小于等于0，则返回错误代码-2
	to_remove = MIN(len, buf->len);
	if (to_remove <= 0) {
		return -2;
	}
    // 更新缓冲区的头部偏移量和头指针
    // head_off 表示缓冲区中当前有效数据的起始偏移量
	buf->head_off += to_remove;
	buf->head = buf->data + buf->head_off;
	buf->head_seq += to_remove;
	buf->len -= to_remove;

	// 如果缓冲区变为空，重置头部指针和头部偏移量
	if (buf->len == 0 && buf->head_off > 0) {
		buf->head = buf->data;
		buf->head_off = buf->tail_off = 0;
	}

	return to_remove;
}



/*** ******************************** sb queue ******************************** ***/


net_sb_queue *CreateSBQueue(int capacity)
{
	net_sb_queue *sq;

	// 分配内存来创建 net_sb_queue 结构体实例
	sq = (net_sb_queue*)calloc(1, sizeof(net_sb_queue));
	if (!sq){
		return NULL;
	}
	// 分配内存来创建一个指针数组，用于存储指向 net_send_buffer 的指针
	sq->_q = (net_send_buffer **)
			calloc(capacity + 1, sizeof(net_send_buffer *));
	if (!sq->_q) {
		free(sq);
		return NULL;
	}

	// 设置队列的容量 初始化
	sq->_capacity = capacity;
	sq->_head = sq->_tail = 0;

	return sq;
}

//销毁
void DestroySBQueue(net_sb_queue *sq) {
	if (!sq)
		return;

	if (sq->_q) {
		free((void *)sq->_q);
		sq->_q = NULL;
	}

	free(sq);
}


int SBEnqueue(net_sb_queue *sq, net_send_buffer *buf) {
	index_type h = sq->_head;
	index_type t = sq->_tail;
	index_type nt = NextIndex(sq, t);

	if (nt != h) {
		sq->_q[t] = buf;
		MemoryBarrier(sq->_q[t], sq->_tail);
		sq->_tail = nt;
		return 0;
	}

	printf("Exceed capacity of buf queue!\n");
	return -1;
}

net_send_buffer *SBDequeue(net_sb_queue *sq)
{
	index_type h = sq->_head;
	index_type t = sq->_tail;

	if (h != t) {
		net_send_buffer *buf = sq->_q[h];
		MemoryBarrier(sq->_q[h], sq->_head);
		sq->_head = NextIndex(sq, h);
		assert(buf);

		return buf;
	}

	return NULL;
}

/*** ******************************** rb_frag queue ******************************** ***/
net_rb_frag_queue *CreateRBFragQueue(int capacity)
{
	net_rb_frag_queue *rb_fragq;

	rb_fragq = (net_rb_frag_queue *)calloc(1, sizeof(net_rb_frag_queue));
	if (!rb_fragq)
		return NULL;

	rb_fragq->_q = (net_fragment_ctx **)
			calloc(capacity + 1, sizeof(net_fragment_ctx *));
	if (!rb_fragq->_q) {
		free(rb_fragq);
		return NULL;
	}

	rb_fragq->_capacity = capacity;
	rb_fragq->_head = rb_fragq->_tail = 0;

	return rb_fragq;
}

void DestroyRBFragQueue(net_rb_frag_queue *rb_fragq) {
	if (!rb_fragq)
		return;

	if (rb_fragq->_q) {
		free((void *)rb_fragq->_q);
		rb_fragq->_q = NULL;
	}

	free(rb_fragq);
}

int RBFragEnqueue(net_rb_frag_queue *rb_fragq, net_fragment_ctx *frag)
{
	index_type h = rb_fragq->_head;
	index_type t = rb_fragq->_tail;
	index_type nt = NextIndex(rb_fragq, t);

	if (nt != h) {
		rb_fragq->_q[t] = frag;
		MemoryBarrier(rb_fragq->_q[t], rb_fragq->_tail);
		rb_fragq->_tail = nt;
		return 0;
	}

	printf("Exceed capacity of frag queue!\n");
	return -1;
}

struct _net_fragment_ctx *RBFragDequeue(net_rb_frag_queue *rb_fragq)
{
	index_type h = rb_fragq->_head;
	index_type t = rb_fragq->_tail;

	if (h != t) {
		struct _net_fragment_ctx *frag = rb_fragq->_q[h];
		MemoryBarrier(rb_fragq->_q[h], rb_fragq->_head);
		rb_fragq->_head = NextIndex(rb_fragq, h);
		assert(frag);

		return frag;
	}

	return NULL;
}

void RBPrintInfo(net_ring_buffer* buff)
{
	printf("buff_data %p, buff_size %d, buff_mlen %d, "
			"buff_clen %lu, buff_head %p (%d), buff_tail (%d)\n", 
			buff->data, buff->size, buff->merged_len, buff->cum_len, 
			buff->head, buff->head_offset, buff->tail_offset);
}

void RBPrintStr(net_ring_buffer* buff)
{
	RBPrintInfo(buff);
	printf("%s\n", buff->head);
}

void RBPrintHex(net_ring_buffer* buff)
{
	int i;

	RBPrintInfo(buff);

	for (i = 0; i < buff->merged_len; i++) {
		if (i != 0 && i % 16 == 0)
			printf("\n");
		printf("%0x ", *( (unsigned char*) buff->head + i));
	}
	printf("\n");
}

net_rb_manager *RBManagerCreate(size_t chunk_size, uint32_t cnum) {
	net_rb_manager *rbm = (net_rb_manager*) calloc(1, sizeof(net_rb_manager));

	if (!rbm) {
		perror("rbm_create calloc");
		return NULL;
	}

	rbm->chunk_size = chunk_size;
	rbm->cnum = cnum;
	rbm->mp = (net_mempool*)net_mempool_create(chunk_size, (uint64_t)chunk_size * cnum, 0);
	if (!rbm->mp) {
		printf("Failed to allocate mp pool.\n");
		free(rbm);
		return NULL;
	}

	rbm->frag_mp = (net_mempool*)net_mempool_create(sizeof(net_fragment_ctx), 
									sizeof(net_fragment_ctx) * cnum, 0);
	if (!rbm->frag_mp) {
		printf("Failed to allocate frag_mp pool.\n");
		net_mempool_destory(rbm->mp);
		free(rbm);
		return NULL;
	}

	rbm->free_fragq = CreateRBFragQueue(cnum);
	if (!rbm->free_fragq) {
		printf("Failed to create free fragment queue.\n");
		net_mempool_destory(rbm->mp);
		net_mempool_destory(rbm->frag_mp);
		free(rbm);
		return NULL;
	}
	rbm->free_fragq_int = CreateRBFragQueue(cnum);
	if (!rbm->free_fragq_int) {
		printf("Failed to create internal free fragment queue.\n");
		net_mempool_destory(rbm->mp);
		net_mempool_destory(rbm->frag_mp);
		DestroyRBFragQueue(rbm->free_fragq);
		free(rbm);
		return NULL;
	}

	return rbm;
}

static inline void FreeFragmentContextSingle(net_rb_manager *rbm, net_fragment_ctx *frag) {
	if (frag->is_calloc)
		free(frag);
	else	
		net_mempool_free(rbm->frag_mp, frag);
}

void FreeFragmentContext(net_rb_manager *rbm, net_fragment_ctx* fctx)
{
	net_fragment_ctx *remove;

	assert(fctx);
	if (fctx == NULL) 	
		return;

	while (fctx) {
		remove = fctx;
		fctx = fctx->next;
		FreeFragmentContextSingle(rbm, remove);
	}
}

static net_fragment_ctx *AllocateFragmentContext(net_rb_manager *rbm) {
	net_fragment_ctx *frag;

	// 从 free_fragq 队列中尝试
	frag = RBFragDequeue(rbm->free_fragq);
	if (!frag) {
		// 从备用的 free_fragq_int 队列中尝试获取 
		frag = RBFragDequeue(rbm->free_fragq_int);
		if (!frag) {
			// 从内存池中分配一个 net_fragment_ctx 结构体
			frag = net_mempool_alloc(rbm->frag_mp);
			if (!frag) {
				printf("fragments depleted, fall back to calloc\n");
				frag = calloc(1, sizeof(net_fragment_ctx));
				if (frag == NULL) {
					printf("calloc failed\n");
					exit(-1);
				}

				// 标记此内存块是通过 calloc 分配的
				frag->is_calloc = 1; 
			}
		}
	}
	memset(frag, 0, sizeof(*frag));
	return frag;
}

net_ring_buffer *RBInit(net_rb_manager *rbm, uint32_t init_seq) {
	net_ring_buffer* buff = (net_ring_buffer*)calloc(1, sizeof(net_ring_buffer));

	if (buff == NULL){
		perror("rb_init buff");
		return NULL;
	}

	buff->data = net_mempool_alloc(rbm->mp);
	if(!buff->data){
		perror("rb_init MPAllocateChunk");
		free(buff);
		return NULL;
	}


	buff->size = rbm->chunk_size;
	buff->head = buff->data;
	buff->head_seq = init_seq;
	buff->init_seq = init_seq;
	
	rbm->cur_num++;

	return buff;
}

void RBFree(net_rb_manager *rbm, net_ring_buffer* buff)
{
	assert(buff);
	if (buff->fctx) {
		FreeFragmentContext(rbm, buff->fctx);
		buff->fctx = NULL;
	}
	
	if (buff->data) {
		net_mempool_free(rbm->mp, buff->data);
	}
	
	rbm->cur_num--;

	free(buff);
}


#define MAXSEQ               ((uint32_t)(0xFFFFFFFF))
/*----------------------------------------------------------------------------*/
static inline uint32_t GetMinSeq(uint32_t a, uint32_t b)
{
	if (a == b) return a;
	if (a < b) 
		return ((b - a) <= MAXSEQ/2) ? a : b;
	return ((a - b) <= MAXSEQ/2) ? b : a;
}
/*----------------------------------------------------------------------------*/
static inline uint32_t GetMaxSeq(uint32_t a, uint32_t b)
{
	if (a == b) return a;
	if (a < b) 
		return ((b - a) <= MAXSEQ/2) ? b : a;
	return ((a - b) <= MAXSEQ/2) ? a : b;
}
/*----------------------------------------------------------------------------*/
static inline int CanMerge(const net_fragment_ctx *a, const net_fragment_ctx *b)
{
	uint32_t a_end = a->seq + a->len + 1;
	uint32_t b_end = b->seq + b->len + 1;

	if (GetMinSeq(a_end, b->seq) == a_end ||
		GetMinSeq(b_end, a->seq) == b_end)
		return 0;
	return (1);
}

static inline void MergeFragments(net_fragment_ctx *a, net_fragment_ctx *b)
{
	uint32_t min_seq, max_seq;

	min_seq = GetMinSeq(a->seq, b->seq);
	max_seq = GetMaxSeq(a->seq + a->len, b->seq + b->len);
	b->seq  = min_seq;
	b->len  = max_seq - min_seq;
}

int RBPut(net_rb_manager *rbm, net_ring_buffer* buff, 
	   void* data, uint32_t len, uint32_t cur_seq) {
	int putx, end_off;
	net_fragment_ctx *new_ctx;
	net_fragment_ctx* iter;
	net_fragment_ctx* prev, *pprev;
	int merged = 0;

	if (len <= 0)
		return 0;

	if (GetMinSeq(buff->head_seq, cur_seq) != buff->head_seq)
		return 0;

	putx = cur_seq - buff->head_seq;
	end_off = putx + len;
	if (buff->size < end_off) {
		return -2;
	}
	
	if ((uint32_t)buff->size <= (buff->head_offset + (uint32_t)end_off)) {
		memmove(buff->data, buff->head, buff->last_len);
		buff->tail_offset -= buff->head_offset;
		buff->head_offset = 0;
		buff->head = buff->data;
	}

	memcpy(buff->head + putx, data, len);

	if (buff->tail_offset < buff->head_offset + end_off) 
		buff->tail_offset = buff->head_offset + end_off;
	buff->last_len = buff->tail_offset - buff->head_offset;

	new_ctx = AllocateFragmentContext(rbm);
	if (!new_ctx) {
		perror("allocating new_ctx failed");
		return 0;
	}
	new_ctx->seq  = cur_seq;
	new_ctx->len  = len;
	new_ctx->next = NULL;

	for (iter = buff->fctx, prev = NULL, pprev = NULL; 
		iter != NULL;
		pprev = prev, prev = iter, iter = iter->next) {
		
		if (CanMerge(new_ctx, iter)) {
			MergeFragments(new_ctx, iter);

			if (prev == new_ctx) {
				if (pprev)
					pprev->next = iter;
				else
					buff->fctx = iter;
				prev = pprev;
			}	
			FreeFragmentContextSingle(rbm, new_ctx);
			new_ctx = iter;
			merged = 1;
		} 
		else if (merged || GetMaxSeq(cur_seq + len, iter->seq) == iter->seq) {
			break;
		} 
	}

	if (!merged) {
		if (buff->fctx == NULL) {
			buff->fctx = new_ctx;
		} else if (GetMinSeq(cur_seq, buff->fctx->seq) == cur_seq) {
			new_ctx->next = buff->fctx;
			buff->fctx = new_ctx;
		} else {
			assert(GetMinSeq(cur_seq, prev->seq + prev->len) ==
				   prev->seq + prev->len);
			prev->next = new_ctx;
			new_ctx->next = iter;
		}
	}
	if (buff->head_seq == buff->fctx->seq) {
		buff->cum_len += buff->fctx->len - buff->merged_len;
		buff->merged_len = buff->fctx->len;
	}
	
	return len;
}

/*----------------------------------------------------------------------------*/
size_t RBRemove(net_rb_manager *rbm, net_ring_buffer* buff, size_t len, int option)
{

	if (buff->merged_len < (int)len) 
		len = buff->merged_len;
	
	if (len == 0) 
		return 0;

	buff->head_offset = len;

	buff->head = buff->data + buff->head_offset;
	buff->head_seq += len;

	buff->merged_len -= len;
	buff->last_len -= len;

	// modify fragementation chunks
	if (len == buff->fctx->len)	{
		net_fragment_ctx* remove = buff->fctx;
		buff->fctx = buff->fctx->next;
		if (option == AT_APP) {
			RBFragEnqueue(rbm->free_fragq, remove);
		} else if (option == AT_MTCP) {
			RBFragEnqueue(rbm->free_fragq_int, remove);
		}
	} else if (len < buff->fctx->len) {
		buff->fctx->seq += len;
		buff->fctx->len -= len;
	} else {
		assert(0);
	}

	return len;
}



net_stream_queue_int *CreateInternalStreamQueue(int size) {
	net_stream_queue_int *sq;

	sq = (net_stream_queue_int *)calloc(1, sizeof(net_stream_queue_int));
	if (!sq) {
		return NULL;
	}

	sq->array = (struct _net_tcp_stream **)calloc(size, sizeof(struct _net_tcp_stream *));
	if (!sq->array) {
		free(sq);
		return NULL;
	}

	sq->size = size;
	sq->first = sq->last = 0;
	sq->count = 0;

	return sq;
}

void DestroyInternalStreamQueue(net_stream_queue_int *sq) {
	if (!sq)
		return;
	
	if (sq->array) {
		free(sq->array);
		sq->array = NULL;
	}

	free(sq);
}

int StreamInternalEnqueue(net_stream_queue_int *sq, struct _net_tcp_stream *stream) {
	if (sq->count >= sq->size) {
		printf("[WARNING] Queue overflow. Set larger queue size! "
				"count: %d, size: %d\n", sq->count, sq->size);
		return -1;
	}

	sq->array[sq->last++] = stream;
	sq->count++;
	if (sq->last >= sq->size) {
		sq->last = 0;
	}
	assert (sq->count <= sq->size);

	return 0;
}

struct _net_tcp_stream *StreamInternalDequeue(net_stream_queue_int *sq) {
	struct _net_tcp_stream *stream = NULL;

	if (sq->count <= 0) {
		return NULL;
	}

	stream = sq->array[sq->first++];
	assert(stream != NULL);
	if (sq->first >= sq->size) {
		sq->first = 0;
	}
	sq->count--;
	assert(sq->count >= 0);

	return stream;
}

int StreamQueueIsEmpty(net_stream_queue *sq)
{
	return (sq->_head == sq->_tail);
}


net_stream_queue *CreateStreamQueue(int capacity) {
	net_stream_queue *sq;

	sq = (net_stream_queue *)calloc(1, sizeof(net_stream_queue));
	if (!sq)
		return NULL;

	sq->_q = (struct _net_tcp_stream **)calloc(capacity + 1, sizeof(struct _net_tcp_stream *));
	if (!sq->_q) {
		free(sq);
		return NULL;
	}

	sq->_capacity = capacity;
	sq->_head = sq->_tail = 0;

	return sq;
}

void DestroyStreamQueue(net_stream_queue *sq)
{
	if (!sq)
		return;

	if (sq->_q) {
		free((void *)sq->_q);
		sq->_q = NULL;
	}

	free(sq);
}

int StreamEnqueue(net_stream_queue *sq, struct _net_tcp_stream *stream) {
	index_type h = sq->_head;
	index_type t = sq->_tail;
	index_type nt = NextIndex(sq, t);

	if (nt != h) {
		sq->_q[t] = stream;
		MemoryBarrier(sq->_q[t], sq->_tail);
		sq->_tail = nt;
		return 0;
	}

	printf("Exceed capacity of stream queue!\n");
	return -1;
}

struct _net_tcp_stream *StreamDequeue(net_stream_queue *sq)
{
	index_type h = sq->_head;
	index_type t = sq->_tail;

	if (h != t) {
		struct _net_tcp_stream *stream = sq->_q[h];
		MemoryBarrier(sq->_q[h], sq->_head);
		sq->_head = NextIndex(sq, h);
		assert(stream);
		return stream;
	}

	return NULL;
}


