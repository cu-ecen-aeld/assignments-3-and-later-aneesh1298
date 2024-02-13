#include "threading.h"
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

// Optional: use these functions to add debug or error prints to your application
#define DEBUG_LOG(msg,...)
//#define DEBUG_LOG(msg,...) printf("threading: " msg "\n" , ##__VA_ARGS__)
#define ERROR_LOG(msg,...) printf("threading ERROR: " msg "\n" , ##__VA_ARGS__)

void* threadfunc(void* thread_param)
{

    // TODO: wait, obtain mutex, wait, release mutex as described by thread_data structure
    // hint: use a cast like the one below to obtain thread arguments from your parameter
    struct thread_data* thread_func_args = (struct thread_data *) thread_param;
    usleep(1000 * thread_func_args->wait_to_obtain_ms);
    //locks the mutex specified in the thread_data structure and point where the thread will obtain the mutex.
    pthread_mutex_lock(thread_func_args->mutex);
    usleep(1000 * thread_func_args->wait_to_release_ms);
    // This is the point where the thread will release the mutex.
    pthread_mutex_unlock(thread_func_args->mutex);
    thread_func_args->thread_complete_success = true;
    return thread_param;
}

/*
 *Description: This function sleeps for wait_to_obtain_ms amount of time to obtain the mutex and then sleeps for 
 * wait_to_release_ms time to release.This function starts the thread and also dynamically allocates memory for 
 * thread data storing. Thread started sucessfully fills thread parameter with the pthread_create thread ID.
 *
 * Parameters: thread : pointer to a pthread_t variable where the function will store the ID of the newly created thread.
 *	       mutex : pointer to the mutex that the thread will obtain and release during its execution.
 *	       wait_to_obtain_ms :Time  the thread should sleep before attempting to obtain the mutex.
 *	       wait_to_release_ms : Time the thread should hold the mutex before releasing it.
 *
 * Return : True if the thread could be started, false if a failure occurred.
 * */
bool start_thread_obtaining_mutex(pthread_t *thread, pthread_mutex_t *mutex,int wait_to_obtain_ms, int wait_to_release_ms)
{
    /**
     * TODO: allocate memory for thread_data, setup mutex and wait arguments, pass thread_data to created thread
     * using threadfunc() as entry point.
     *
     * return true if successful.
     *
     * See implementation details in threading.h file comment block
     */

     // Allocate memory for thread_data dynamically using malloc
     struct thread_data* pointer_thread_data = (struct thread_data*)malloc(sizeof(struct thread_data));
     //If memory cant be allocated-- ie pointer resembles NULL
     if(pointer_thread_data == NULL)
     {
	     ERROR_LOG("Memory Allocation failed to thread structure");
	     return false;
     }

     // Filling thread data
    pointer_thread_data->thread_complete_success = false;
    pointer_thread_data->mutex = mutex;
    pointer_thread_data->wait_to_obtain_ms = wait_to_obtain_ms;
    pointer_thread_data->wait_to_release_ms = wait_to_release_ms;
    // Start the thread
    int thread_start_result = pthread_create(thread, NULL, threadfunc, (void*)pointer_thread_data);
    if (thread_start_result != 0)
    {
        ERROR_LOG("THread Creation Failed");
	//Deallocating memory
        free(pointer_thread_data);
        return false;
    }
    return true;
}

