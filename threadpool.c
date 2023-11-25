#include <stdio.h>
#include <stdlib.h>
#include "threadpool.h"

/**
 * create_threadpool creates a fixed-sized thread
 * pool.  If the function succeeds, it returns a (non-NULL)
 * "threadpool", else it returns NULL.
 */
threadpool* create_threadpool(int num_threads_in_pool){
  int i;

  //1. input sanity check
  if((num_threads_in_pool < 0) || (num_threads_in_pool > MAXT_IN_POOL)){
    fprintf(stderr, "Error: Invalid pool size\n");
    return NULL;
  }

  threadpool* tp = (threadpool*) calloc(1, sizeof(threadpool));
  if(tp == NULL){
    perror("malloc");
    return NULL;
  }

  //2. initialize the threadpool structure
  tp->num_threads = num_threads_in_pool;
  tp->qhead = tp->qtail = NULL;

  tp->threads = (pthread_t *) malloc(sizeof(pthread_t)*tp->num_threads);
  if(tp->threads == NULL){
    perror("malloc");
    return NULL;
  }

  //3. initialized mutex and conditional variables
  if(pthread_mutex_init(&tp->qlock, NULL) != 0){
    perror("pthread_mutex_init");
    return NULL;
  }

  if( (pthread_cond_init(&tp->q_not_empty, NULL) != 0) ||
      (pthread_cond_init(&tp->q_not_empty, NULL) != 0) ){
    perror("pthread_cond_init");
    return NULL;
  }

  //4. create the threads, the thread init function is do_work
  //and its argument is the initialized threadpool.
  for(i=0; i < tp->num_threads; i++){
    if(pthread_create(&tp->threads[i], NULL, do_work, (void*)tp) != 0){
      perror("pthread_create");
      return NULL;
    }
  }

  return tp;
}


/**
 * dispatch enter a "job" of type work_t into the queue.
 * when an available thread takes a job from the queue, it will
 * call the function "dispatch_to_here" with argument "arg".
 * this function should:
 */
void dispatch(threadpool* tp, dispatch_fn dispatch_to_here, void *arg){

  //1. create and init work_t element
  work_t * work = (work_t*) malloc(sizeof(work_t));
  if(work == NULL){
    perror("malloc");
    return;
  }

  work->routine = dispatch_to_here;
  work->arg = arg;
  work->next = NULL;

  // 2. lock the mutex
  pthread_mutex_lock(&tp->qlock);

  if(tp->dont_accept){
    free(work);
    pthread_mutex_unlock(&tp->qlock);
    return;
  }

  //3. add the work_t element to the queue
  if(tp->qsize == 0){
    tp->qhead = tp->qtail = work;
  }else {
    tp->qtail->next = work;
    tp->qtail = work;
  }
  tp->qsize++;
  pthread_cond_signal(&tp->q_not_empty);

  //4. unlock mutex
  pthread_mutex_unlock(&tp->qlock);
}

/**
 * The work function of the thread
 * this function should:
 */
void* do_work(void* p){

  threadpool* tp = (threadpool*) p;

  while(1){
    //1. lock mutex
    pthread_mutex_lock(&tp->qlock);

    //if destruction process has begun
    if(tp->shutdown){
      pthread_mutex_unlock(&tp->qlock);
      //exit loop
      break;
    }

    //2. if the queue is empty, wait
    while((tp->qsize == 0) &&
          (tp->shutdown == 0)){
      pthread_cond_wait(&tp->q_not_empty, &tp->qlock);
    }

    if(tp->shutdown){
      //4. unlock mutex
      pthread_mutex_unlock(&tp->qlock);
      break;
    }

    //3. take the first element from the queue (work_t)
    work_t * work = tp->qhead;
    tp->qhead = tp->qhead->next;
    if(--tp->qsize == 0){
      tp->qtail = NULL;
    }

    //if queue is empty and destruction process in place
    if(tp->qsize == 0){
      //signal waiting destruction process
      pthread_cond_signal(&tp->q_empty);
    }
    //4. unlock mutex
    pthread_mutex_unlock(&tp->qlock);

    //5. call the thread routine
    work->routine(work->arg);

    free(work);
  }

  pthread_exit(NULL);
}

/**
 * destroy_threadpool kills the threadpool, causing
 * all threads in it to commit suicide, and then
 * frees all the memory associated with the threadpool.
 */
void destroy_threadpool(threadpool* tp){
  int i;

  // signal poll its shutting down
  pthread_mutex_lock(&tp->qlock);
  tp->dont_accept = 1;
  pthread_mutex_unlock(&tp->qlock);


  pthread_mutex_lock(&tp->qlock);

  while(tp->qsize > 0){
    pthread_cond_wait(&tp->q_empty, &tp->qlock);
  }
  tp->shutdown = 1;
  pthread_cond_broadcast(&tp->q_not_empty);

  pthread_mutex_unlock(&tp->qlock);

  //wait for threads to complete
  for(i=0; i < tp->num_threads; i++){
    pthread_join(tp->threads[i], NULL);
  }

  //destroy pthread variables
  pthread_cond_destroy(&tp->q_not_empty);
  pthread_cond_destroy(&tp->q_empty);
  pthread_mutex_destroy(&tp->qlock);

  //release resources
  free(tp->threads);
  free(tp);

}