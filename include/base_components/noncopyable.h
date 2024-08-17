#ifndef _NONCOPYABLE_H
#define _NONCOPYABLE_H

/*
禁止拷贝操作的基类，设置为protect权限的成员函数可以让派生类继承
派生类对象可以正常的构造和析构
*/

// noncopyable  避免编译器自动生成默认的拷贝构造函数和拷贝赋值运算
class noncopyable
{
public:
    noncopyable(const noncopyable &) = delete;
    noncopyable &operator=(const noncopyable &) = delete;

protected:
    noncopyable() = default;
    ~noncopyable() = default;
};

#endif