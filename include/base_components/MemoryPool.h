#ifndef _MEMORY_POOL_H
#define _MEMORY_POOL_H

//4 kb 标准页面大小
const int  PAGE_SIZE=4096;
// 按照16字节对齐
const int MP_ALIGNMENT=16;
//计算按照alignment字节对齐后的大小
#define mp_align(n, alignment) (((n)+(alignment-1)) & ~(alignment-1))
//将指针p按照alignment字节对齐
#define mp_align_ptr(p, alignment) (void *)((((size_t)p)+(alignment-1)) & ~(alignment-1))

struct SmallNode
{
    unsigned char* end_;     // 该块的结尾
    unsigned char* last_;    // 该块目前使用位置
    unsigned int quote_;     // 该块被引用次数
    unsigned int failed_;    // 该块失效次数
    struct SmallNode* next_; // 指向下一个块
}; 

struct LargeNode
{
    void* address_;          // 该块的起始地址
    unsigned int size_;      // 该块大小
    struct LargeNode* next_; // 指向下一个大块
};

struct Pool
{
    LargeNode* largeList_;   // 管理大块内存链表
    SmallNode* head_;        // 头节点
    SmallNode* current_;     // 指向当前分配的块，这样可以避免遍历前面已经不能分配的块  
};

class MemoryPool
{
public:
    // 指定为默认实现  初始化交给createpool 析构交给destroypool
    MemoryPool()=default;
    ~MemoryPool()=default;
    //初始化内存池，为 pool_ 分配 PAGE_SIZE 内存
    bool createPool();
    //遍历大小内存块 释放
    void destroyPool();
    //申请内存的接口，内部会判断创建大块还是小块内存
    void* malloc(unsigned long size);
    //申请内存且将内存清零，内部调用 malloc
    void* calloc(unsigned long size);
    //释放内存指定内存
    void freeMemory(void* p);
    //重置内存池
    void resetPool();
    Pool* getPool() { return pool_; }
private:
    void* mallocLargeNode(unsigned long size);
    void* mallocSmallNode(unsigned long size);
    Pool* pool_ = nullptr;    
};


#endif