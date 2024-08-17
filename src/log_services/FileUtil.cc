#include "log_services/FileUtil.h"
#include "log_services/Logging.h"
FileUtil::FileUtil(std::string& file): 
    fp_(::fopen(file.c_str(), "ae")),//追加模式打开文件
    writtenBytes_(0)
{
    //后续的 I/O 操作可以直接使用该缓冲区 减少磁盘访问
    ::setbuffer(fp_,buffer_,sizeof(buffer_));
}

FileUtil::~FileUtil()
{
    ::fclose(fp_);
}

void FileUtil::append(const char* data, size_t len)
{
    printf("FileUtil::append %d\n",len);
    // 记录已经写入的数据大小
    size_t written = 0;
    while (written != len)
    {
        // 还需写入的数据大小
        size_t remain = len - written;
        size_t n = write(data + written, remain);
        if (n != remain)
        {
            int err = ferror(fp_);
            if (err)
            {
                fprintf(stderr, "FileUtil::append() failed %s\n", getErrnoMsg(err));
            }
        }
        // 更新写入的数据大小
        written += n;
    }
    // 记录目前为止写入的数据大小，超过限制会滚动日志
    writtenBytes_ += written;
}

void FileUtil::flush()
{
    //刷新流的缓冲区，确保缓冲区中的数据被写入到对应的文件
    ::fflush(fp_);
}

size_t FileUtil::write(const char* data, size_t len)
{// 使用不加锁的写入函数 保证性能
    
    //size_t fwrite(const void* buffer, size_t size, size_t count, FILE* stream);
    // -- buffer:指向数据块的指针
    // -- size:每个数据的大小，单位为Byte(例如：sizeof(int)就是4)
    // -- count:数据个数
    // -- stream:文件指针
    return ::fwrite_unlocked(data, 1, len, fp_);
}