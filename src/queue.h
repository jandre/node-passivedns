// Copyright 2012. Matt Tierney. BSD Style License.
// Author: tierney@cs.nyu.edu (Matt Tierney)

#ifndef _QUEUE_H_
#define _QUEUE_H_

#include <ctime>
#include <deque>
#include <pthread.h>
#include <sys/time.h>
#include "defines.h"


#define CHECK_EQ(val1, val2) if (val1 != val2) elog("Fatal Error\n");
#define CHECK_NOTNULL(val1) if (val1 == NULL) elog("Value is null!\n");


#define LOCK_MUTEX(mutex)\
    do {\
        dlog("%x Lock requested: %d\n",  mutex, (unsigned int)pthread_self());\
        CHECK_EQ(pthread_mutex_lock(mutex), 0);\
        dlog("Lock acquired: %d\n",  (unsigned int)pthread_self());\
    } while(0);


#define UNLOCK_MUTEX(mutex)\
    do {\
        dlog("%x Unlocked: %d\n",  mutex, (unsigned int)pthread_self());\
        CHECK_EQ(pthread_mutex_unlock(mutex), 0);\
        dlog("Unlocked success: %d\n",  (unsigned int)pthread_self());\
    } while(0);

// This Queue class follows the concurrency patterns and API of the python Queue
// collection. The user may specify a maximum size for the internal queue
// storage.
// 
// This class currently contains a hard-coded underlying storage 
// container, the std::deque.
//
// This class is thread-safe.
template<typename T>
class Queue {
 public:
  explicit Queue(int maxsize) : maxsize_(maxsize), unfinished_tasks_(0) {
    CHECK_EQ(pthread_cond_init(&all_tasks_done_, NULL), 0);
    CHECK_EQ(pthread_cond_init(&not_empty_, NULL), 0);
    CHECK_EQ(pthread_cond_init(&not_full_, NULL), 0);
    CHECK_EQ(uv_mutex_init(&mutex_), 0);
  }

  virtual ~Queue() {
    printf("XXX QUEUE DESTROYED\n");
  }

  void task_done() {
    LOCK_MUTEX(&mutex_)
    int unfinished = unfinished_tasks_ - 1;
    if (unfinished <= 0) {
      if (unfinished < 0) {
        // LOG(FATAL) << "ValueError task_done() called too many times.";
      }
      pthread_cond_broadcast(&all_tasks_done_);
    }
    unfinished_tasks_ = unfinished;
    UNLOCK_MUTEX(&mutex_)
  }

  void join() {
    LOCK_MUTEX(&mutex_)
    while (unfinished_tasks_ > 0) {
      pthread_cond_wait(&all_tasks_done_, &mutex_);
    }
    UNLOCK_MUTEX(&mutex_)
  }

  int qsize() {
    LOCK_MUTEX(&mutex_)
    int n = queue_.size();
    UNLOCK_MUTEX(&mutex_)
    return n;
  }

  bool empty() {
    LOCK_MUTEX(&mutex_)
    bool ret = queue_.size() > 0 ? false : true;
    UNLOCK_MUTEX(&mutex_)
    return ret;
  }

  bool full() {
    LOCK_MUTEX(&mutex_)
    bool ret = 0 < queue_.size() == maxsize_;
    UNLOCK_MUTEX(&mutex_)
    return ret;
  }

  bool put(const T& item, bool block, time_t timeout) {
    LOCK_MUTEX(&mutex_)
    if (maxsize_ > 0) {
      if (!block) {
        if (queue_.size() == maxsize_) {
          // LOG(ERROR) << "Queue is full.";
          UNLOCK_MUTEX(&mutex_)
          return false;
        } else if (timeout == 0) {
          while (queue_.size() == maxsize_) {
            pthread_cond_wait(&not_full_, &mutex_);
          }
        } else if (timeout < 0) {
          UNLOCK_MUTEX(&mutex_)
          // LOG(FATAL) << "'timeout' must be a positive number";
        } else {
          time_t endtime = time(NULL) + timeout;
          while (queue_.size() == maxsize_) {
            time_t remaining = endtime - time(NULL);
            if (remaining <= 0.0) {
              UNLOCK_MUTEX(&mutex_)
              return false;
            }

            // Following example from 'man pthread_cond_timedwait' to figure out
            // what is the remaining time to call a pthread conditional variable
            // timed wait.
            struct timeval tv;
            struct timespec ts;
            gettimeofday(&tv, NULL);
            ts.tv_sec = tv.tv_sec + remaining;
            ts.tv_nsec = 0;
            
            pthread_cond_timedwait(&not_full_, &mutex_, &ts);
          }
        }

      }
    }
    _put(item);
    unfinished_tasks_++;
    pthread_cond_signal(&not_empty_);
    UNLOCK_MUTEX(&mutex_)
    return true;
  }

  bool put_nowait(const T& item) {
    return put(item, false, 0);
  }
  
  // @timeout == 0 means that no timeout is used.
  bool get(bool block, time_t timeout, T* output) {
    CHECK_NOTNULL(output);

    LOCK_MUTEX(&mutex_)
    if (!block) {
      if (0 == queue_.size()) {
        UNLOCK_MUTEX(&mutex_)
        return false;
      }
    } else if (timeout == 0) {
      while (queue_.size() == 0) {
        pthread_cond_wait(&not_empty_, &mutex_);
      }
    } else if (timeout < 0) {
      UNLOCK_MUTEX(&mutex_)
      // LOG(FATAL) << "'timeout' must be a positive number";
    } else {
      time_t endtime = time(NULL) + timeout;
      while (0 == queue_.size()) {
        time_t remaining = endtime - time(NULL);
        if (remaining <= 0.0) {
          UNLOCK_MUTEX(&mutex_)
          return false;
        }
        pthread_cond_wait(&not_empty_, &mutex_);
      }
    }

    _get(output);
    pthread_cond_signal(&not_full_);
    UNLOCK_MUTEX(&mutex_)
    return true;
  }

  bool get_nowait(T* output) {
    CHECK_NOTNULL(output);
    return get(false, 0, output);
  }
  
 private:
  void _put(const T& item) {
    queue_.push_back(item);
  }

  void _get(T* output) {
    CHECK_NOTNULL(output);
    *output = queue_.front();
    queue_.pop_front();
  }
  
  pthread_cond_t all_tasks_done_;
  pthread_cond_t not_empty_;
  pthread_cond_t not_full_;
  pthread_mutex_t mutex_;

  int maxsize_;
  int unfinished_tasks_;

  std::deque<T> queue_;

  // DISALLOW_COPY_AND_ASSIGN(Queue);
  Queue(const Queue&);
  void operator=(const Queue&);
};

#endif  // _QUEUE_H_
