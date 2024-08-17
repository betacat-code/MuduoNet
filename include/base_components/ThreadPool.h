#ifndef THREAD_POOL_H
#define THREAD_POOL_H

#include "base_components/noncopyable.h"
#include <condition_variable>
#include <functional>
#include <future>
#include <memory>
#include <mutex>
#include <queue>
#include <thread>
#include <utility>
#include <vector>

class ThreadPool :noncopyable
{
 public:
  explicit ThreadPool(size_t);
  template <typename F, typename... Args>
  auto enqueue(F&& f, Args&&... args) -> std::future<typename std::result_of<F(Args...)>::type>;
  ~ThreadPool();

 private:
  std::vector<std::thread> workers_;
  std::queue<std::function<void()>> tasks_;

  std::mutex queue_mutex_;
  std::condition_variable condition_;
  bool stop_;
};

inline ThreadPool::ThreadPool(size_t threads) : stop_(false) 
{
  for (size_t i = 0; i < threads; ++i) 
  {
    workers_.emplace_back([this] 
    {
      for (;;) {
        std::function<void()> task;
        {
          std::unique_lock<std::mutex> lock(this->queue_mutex_);
          this->condition_.wait(lock, [this] 
          {
            // 线程池被停止 或者有有任务再继续往下执行
            return this->stop_ || !this->tasks_.empty();
          });
          if (this->stop_ && this->tasks_.empty()) 
          {
            // 线程池停止了 的同时没任务就不执行了
            return;
          }
          task = std::move(this->tasks_.front());
          this->tasks_.pop();
        }
        task();
      }
    });
  }
}

//传递多个参数包 Args &&完美引用
template <class F, class... Args>
auto ThreadPool::enqueue(F&& f, Args&&... args) -> 
  std::future<typename std::result_of<F(Args...)>::type> // 返回类型后置
{
  using return_type = typename std::result_of<F(Args...)>::type;

  auto task =
      std::make_shared<std::packaged_task<return_type()>>(std::bind(std::forward<F>(f), std::forward<Args>(args)...));
      //packaged_task 异步任务
  std::future<return_type> res = task->get_future();
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    if (stop_) 
    {
      throw std::runtime_error("enqueue on stopped ThreadPool");
    }
    tasks_.emplace([task]() 
    {
      (*task)();
    });
  }
  condition_.notify_one();
  return res;
}

inline ThreadPool::~ThreadPool() 
{
  {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    stop_ = true;
  }
  condition_.notify_all();
  for (std::thread& worker : workers_) 
  {
    if (worker.joinable()) 
    {
      worker.join();
    }
  }
}
#endif