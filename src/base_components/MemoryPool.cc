#include "base_components/MemoryPool.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <error.h>
bool MemoryPool::createPool()
{
    printf("MemoryPool::createPool\n");
    int ret = posix_memalign((void **)&pool_, MP_ALIGNMENT, PAGE_SIZE);
    if(ret==0)
    {
        printf("posix_memalign failed error\n");
        return false;
    }
    // 分配 PAGE_SIZE 内存：Pool + SmallNode + 剩余可用内存
    pool_->largeList_ = nullptr;
    pool_->head_ = (SmallNode *)((unsigned char*)pool_ + sizeof(Pool));
    pool_->head_->last_ = (unsigned char*)pool_ + sizeof(Pool) + sizeof(SmallNode);
    pool_->head_->end_ = (unsigned char*)pool_ + PAGE_SIZE;
    pool_->head_->failed_ = 0;
    pool_->current_ = pool_->head_;

    return true;
}

void MemoryPool::destroyPool()
{
    LargeNode* large = pool_->largeList_;
    while(large!=nullptr)
    {
        if(large!=nullptr)
        {
            free(large->address_);
            large->address_=nullptr;
        }
        large=large->next_;
    }

    SmallNode* cur = pool_->head_->next_;
    SmallNode* next=nullptr;
    while (cur!=nullptr)
    {
        next=cur->next_;
        free(cur);
        cur=next;
    }
    free(pool_);
}

void* MemoryPool::mallocLargeNode(unsigned long size)
{
    unsigned char* addr;
    int ret = posix_memalign((void**)&addr, MP_ALIGNMENT, size);
    if(ret==0)
    {
        printf("posix_memalign failed\n");
        return nullptr;
    }
    int counts=0;
    LargeNode* largeNode = pool_->largeList_;
    while(largeNode!=nullptr)
    {
        if(largeNode->address_==nullptr)
        {
            largeNode->size_ = size;
            largeNode->address_ = addr;
            //把整个申请的内存都给出去了
            return addr;
        }
        if(counts++>3)
        {
            // 为了避免过多的遍历，限制次数
            break;
        }
        largeNode = largeNode->next_;
    }

    // 没有找到空闲的large结构体，分配一个新的large
    largeNode = (LargeNode*)this->malloc(sizeof(LargeNode));
    // 先是申请了一个LargeNode 结构体来管理申请的addr
    if(largeNode==nullptr)
    {
        free(addr);// 申请节点内存失败，需要释放之前申请的大内存
        return nullptr;
    }

    largeNode->size_ = size;    // 设置新块大小
    largeNode->address_ = addr; // 设置新块地址
    // 下面用头插法方式将新块加入到 largeList 的头部
    largeNode->next_ = pool_->largeList_; 
    pool_->largeList_ = largeNode;
    return addr;
}

//创建新SmallNode块 
void* MemoryPool::mallocSmallNode(unsigned long size)
{
    unsigned char* block;
    int ret = posix_memalign((void**)&block, MP_ALIGNMENT, PAGE_SIZE);
    if (ret)
    {
        return nullptr;
    }
    // 获取新块的 smallnode 节点
    SmallNode* smallNode = (SmallNode*)block;
    smallNode->end_ = block + PAGE_SIZE;
    smallNode->next_ = nullptr;

    // 分配新块的起始位置
    unsigned char* addr = (unsigned char*)mp_align_ptr(block + sizeof(SmallNode), MP_ALIGNMENT);
    smallNode->last_ = addr + size;
    smallNode->quote_++;
    //
    SmallNode* current = pool_->current_;
    SmallNode* cur = current;

    while (cur->next_ != nullptr)
    {
        // 失效 block 数量过大，直接跳过这些 block，减少遍历次数
        // 超过五个不能用的块，更新current指针
        if (cur->failed_ >= 5)
        {
            current = cur->next_;
        }
        cur->failed_++;
        cur = cur->next_;
    }
    // cur已经到了最后一个 连接上申请的smallNode
    cur->next_ = smallNode;
    pool_->current_ = current;
    return addr;
}

void* MemoryPool::malloc(unsigned long size)
{
    if(size<=0)
    {
        return nullptr;
    }
    // 申请大块内存
    if (size > PAGE_SIZE - sizeof(SmallNode))
    {
        return mallocLargeNode(size);
    }
    // 申请小块内存
    unsigned char* addr = nullptr;
    SmallNode* cur = pool_->current_;
    while (cur) 
    {
        // 将cur->last指向处，格式化成16整数倍
        addr = (unsigned char*)mp_align_ptr(cur->last_, MP_ALIGNMENT);
        // 说明该 block 剩余位置足够分配
        if(cur->end_-addr>=size)
        {
            cur->quote_++; // 该 block 被引用次数增加
            cur->last_ = addr + size; // 更新已使用位置
            return addr;
        }
        //此block不够用，去下一个block
        cur = cur->next_;
    }
    // 说明已有的 block 都不够用，需要创建新的 block
    return mallocSmallNode(size);
}

void* MemoryPool::calloc(unsigned long size)
{
    void* addr = malloc(size);
    if (addr != nullptr)
    {
        memset(addr, 0, size);
    }
    return addr;
}

void MemoryPool::freeMemory(void* p)
{
    LargeNode* large = pool_->largeList_;
    while (large != nullptr)
    {
        if (large->address_ == p)
        {
            free(large->address_);
            large->size_ = 0;
            large->address_ = nullptr;
            return;
        }
        large = large->next_;
    }
    SmallNode* small=pool_->head_;
    while(small)
    {
        if ((unsigned char*)small <= (unsigned char*)p &&
            (unsigned char *) p <= (unsigned char *)small->end_)
        {
            --small->quote_;
            if(small->quote_==0)
            {
                if(small==pool_->head_)
                {
                    pool_->head_->last_ = (unsigned char *)pool_ + sizeof(Pool) + sizeof(SmallNode);
                }
                else
                {
                    // last指针回到node节点尾处
                    small->last_ = (unsigned char *)small + sizeof(SmallNode);
                }
                small->failed_=0;
                pool_->current_=pool_->head_;
            }
            return ;
        }
        small=small->next_;
    }
}

void MemoryPool::resetPool()
{
    SmallNode* small = pool_->head_;
    LargeNode* large = pool_->largeList_;

    while (large != nullptr)
    {
        if (large->address_)
        {
            free(large->address_);
        }
        large = large->next_;
    }

    pool_->largeList_ = nullptr;
    pool_->current_ = pool_->head_;
    while (small != nullptr)
    {
        small->last_ = (unsigned char*)small + sizeof(SmallNode);
        small->failed_ = 0;
        small->quote_ = 0;
        small = small->next_;
    }
}