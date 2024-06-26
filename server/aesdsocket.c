#include "queue.h"
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h> //has the struct addrinfo variable here
#include <netinet/in.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include "../aesd-char-driver/aesd_ioctl.h"

#define PORT "9000"
#define USE_AESD_CHAR_DEVICE   (1)
#if (USE_AESD_CHAR_DEVICE == 0)
    #define DATA_FILE           "/var/tmp/aesdsocketdata"
#elif (USE_AESD_CHAR_DEVICE == 1)
    #define DATA_FILE           "/dev/aesdchar"
#endif
#define BUF_SIZE 1024
#define BUFF_SIZE 1024
#define INPUTS_MATCHED   2

int socket_fd = 0;
int client_socket_fd = 0;
int file_fd = 0;
int transfer_exit = 0;
int status = 0;

typedef struct socket_node {
  pthread_t my_thread_id;
  int client_socket_fd;
  bool my_thread_complete;
  pthread_mutex_t *thread_mutex;
  SLIST_ENTRY(socket_node) node_next;
} socket_node_t;

typedef enum status {
  Socket_created,
  client_socket,
  thread_close,
  file_work
} transfer_status_t;
char ip_addr[INET_ADDRSTRLEN];

//* Extracts the IP address from a sockaddr structure, supporting both IPv4 and
//* IPv6. Argument is a pointer to a sockaddr structure representing the address
//* information. Returns a void pointer to the extracted IP address.
void *get_in_addr(struct sockaddr *sa) {
  if (sa->sa_family == AF_INET) {
    return &(((struct sockaddr_in *)sa)->sin_addr);
  }

  return &(((struct sockaddr_in6 *)sa)->sin6_addr);
}

/*
 * Handles errors during data transfer, closing relevant file descriptors and
 * cleaning up resources. transfer_status: An enumeration indicating the stage
 * of the data transfer where the error occurred. It can have values: socket,
 * client_socket, or transfer_complete.
 */
void error_handler(transfer_status_t transfer_status) {
  // Close socket_fd and log closure message if the error occurred at the socket
  // stage.
  if (transfer_status == Socket_created) {
    close(socket_fd);
      #if (USE_AESD_CHAR_DEVICE == 0)
  	remove(DATA_FILE);
  	#endif
    syslog(LOG_INFO, "CLOSE socket_fd: %d", socket_fd);
  }
  // Close socket_fd and client_socket_fd, and log closure messages if the error
  // occurred at the client_socket stage.
  else if (transfer_status == client_socket) {
    close(socket_fd);
      #if (USE_AESD_CHAR_DEVICE == 0)
  	remove(DATA_FILE);
  	#endif
  	  syslog(LOG_INFO, "CLOSE socket_fd: %d", socket_fd);
    close(client_socket_fd);
    syslog(LOG_INFO, "CLOSE client_socket_fd: %d", client_socket_fd);
  } else if (transfer_status == thread_close) {
    close(client_socket_fd);
      #if (USE_AESD_CHAR_DEVICE == 0)
  	remove(DATA_FILE);
  	#endif
    syslog(LOG_INFO, "CLOSE client_socket_fd: %d", client_socket_fd);
    if (file_fd != -1) {
      close(file_fd);
        #if (USE_AESD_CHAR_DEVICE == 0)
  	remove(DATA_FILE);
  	#endif
      syslog(LOG_INFO, "FILE closure: %d", file_fd);
    }
    return;
  }
  // Close socket_fd, client_socket_fd, and file_fd, and log closure messages if
  // the error occurred at the transfer_complete stage.
  else {
    close(socket_fd);
    syslog(LOG_INFO, "CLOSE socket_fd: %d", socket_fd);
      #if (USE_AESD_CHAR_DEVICE == 0)
  remove(DATA_FILE);
  #endif
    close(client_socket_fd);
    syslog(LOG_INFO, "CLOSE client_socket_fd: %d", client_socket_fd);
    close(file_fd);
    syslog(LOG_INFO, "FILE closure: %d", file_fd);
  }
  closelog();
  #if (USE_AESD_CHAR_DEVICE == 0)
  remove(DATA_FILE);
  #endif
}

/**
 * Handles signals, specifically SIGINT and SIGTERM, initiating a graceful exit
 *of the data transfer process. signal_number: An integer representing the
 *received signal number.
 **/
void signal_handler(int signal_number) {
  if ((signal_number == SIGINT) || (signal_number == SIGTERM)) {
    transfer_exit = 1;
    syslog(LOG_DEBUG, "Caught signal, exiting");
    error_handler(file_work);
    //exit(EXIT_SUCCESS);
  }
}


#if (USE_AESD_CHAR_DEVICE == 0)
void *timestamp_thread(void *thread_node) {
  if (NULL == thread_node) {
    return NULL;
  }
  int status=0;
  int file_fd = -1;
  struct timespec time_period;
  char output[BUFF_SIZE] = {'\0'};
  time_t current_time;
  struct tm *local_time;
  int characters_written = 0;
  socket_node_t *temp_node = thread_node;
  temp_node->my_thread_complete= false;
  while (!transfer_exit) {
    if (clock_gettime(CLOCK_MONOTONIC, &time_period) != 0) {
      syslog(LOG_ERR, "ERROR: Failed to get time");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
      //return thread_node;
      close(file_fd);
      status=0;
      goto exit;
    }
    time_period.tv_sec += 10;

    if (clock_nanosleep(CLOCK_MONOTONIC, TIMER_ABSTIME, &time_period, NULL) !=
        0) {
      syslog(LOG_ERR, "ERROR: Failed to sleep for 10 sec");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
      //return thread_node;
      close(file_fd);
      status=0;
      goto exit;
    }
    current_time =time(NULL);
    if ((current_time) == -1) {
      syslog(LOG_ERR, "ERROR: Failed to get current time");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
      //return thread_node;
      close(file_fd);
      status=0;
      goto exit;
    }
    local_time = localtime(&current_time);
    if (NULL == local_time) {
      syslog(LOG_ERR, "ERROR: Failed to fill tm struct");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
      //return thread_node;
      close(file_fd);
      status=0;
      goto exit;
    }

    characters_written = strftime(
        output, sizeof(output), "timestamp: %Y %B %d, %H:%M:%S\n", local_time);
    if (0 == characters_written) {
      syslog(LOG_ERR, "ERROR: Failed to convert tm into string");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
      //return thread_node;
      close(file_fd);
      status=0;
      goto exit;
    }

    file_fd = open(DATA_FILE, O_CREAT | O_RDWR | O_APPEND,
                   S_IWUSR | S_IRUSR | S_IWGRP | S_IRGRP | S_IROTH);
    if (file_fd == -1) {
      syslog(LOG_ERR, "ERROR: Failed to create/open file");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
     // return thread_node;
     close(file_fd);
     status=0;
     goto exit;
    }
    if (pthread_mutex_lock(temp_node->thread_mutex) != 0) {
      syslog(LOG_ERR, "ERROR: Failed to lock mutex");
      //temp_node->my_thread_complete = false;
      //close(file_fd);
     // return thread_node;
     close(file_fd);
     status=0;
     goto exit;
    }
    // Writing the timestamp
    characters_written = write(file_fd, output, strlen(output));
    if (characters_written != strlen(output)) {
      syslog(LOG_ERR, "ERROR: Failed to write timestamp to file");
      //temp_node->my_thread_complete = false;
      pthread_mutex_unlock(temp_node->thread_mutex);
      status=0;
      close(file_fd);
      goto exit;
    }
    if (pthread_mutex_unlock(temp_node->thread_mutex) != 0) {
      syslog(LOG_ERR, "ERROR: Failed to unlock mutex");
      status=0;
      close(file_fd);
      goto exit;
    }
    status=1;
    //temp_node->my_thread_complete = true;
    close(file_fd);
  }
  
  exit:
  //close(file_fd);
  if(status==0)
  {
  	temp_node->my_thread_complete = false;
  }else
  {
  	temp_node->my_thread_complete = true;
  }

  return thread_node;
}

#endif


void *data_thread(void *thread_node) {

  char buf[BUF_SIZE];
  int packet_receive_complete = 0;
  socket_node_t *node = (socket_node_t *)thread_node;
  node->my_thread_complete = false;
  int status=0;
  int file_fd = -1;
  
  #if (USE_AESD_CHAR_DEVICE == 1)
    	const char *ioctl_str = "AESDCHAR_IOCSEEKTO:";
  #endif
  if (thread_node == NULL) {
    return NULL;
  }
  file_fd = open(DATA_FILE, O_CREAT | O_RDWR | O_APPEND, 0744);
  if (file_fd == -1) {
    syslog(LOG_ERR,
           "ERROR: Failed to  OPEN the FILE at %s",DATA_FILE);
      perror("Aneesh");
      status=-1;
	goto exit;
    // exit(EXIT_FAILURE);
  }

  while (packet_receive_complete !=1) {
    // bzero(buf, BUF_SIZE);
    
    memset(buf, 0, BUF_SIZE);
    int n_received = recv(node->client_socket_fd, buf, 1024, 0);
    // printf("\n\r data received is %s\n\r",buf);
    if (n_received == -1) {
      syslog(LOG_ERR, "ERROR: Failed to RECEIVE data");
      status=-1;
      //pthread_mutex_unlock(node->thread_mutex);
	goto exit;
      // exit(EXIT_FAILURE);
    }

   #if (USE_AESD_CHAR_DEVICE == 1)
         if ( strncmp(buf, ioctl_str, strlen(ioctl_str)) ==0)
         {
                struct aesd_seekto data_seeking;
                if (INPUTS_MATCHED != sscanf(buf, "AESDCHAR_IOCSEEKTO:%d,%d",
                                                   &data_seeking.write_cmd,
                                                   &data_seeking.write_cmd_offset))
                {
                    syslog(LOG_PERROR, "sscanf: %s", strerror(errno));
                }
                else
                {
                    if(ioctl(file_fd, AESDCHAR_IOCSEEKTO, &data_seeking) !=0 )
                    {
                        syslog(LOG_PERROR, "ioctl: %s", strerror(errno));
                    }
                }
                goto data_reading;
            	}
    #endif

    if (pthread_mutex_lock(node->thread_mutex) != 0) {
      syslog(LOG_ERR, "ERROR: Failed to lock mutex");
      status=-1;
	goto exit;
    }

    int n_written = write(file_fd, buf, n_received);
    //printf("\n\r data writing to file  is %s\n\r", buf);
    if ((n_written != n_received)) {
      syslog(LOG_ERR, "ERROR: Failed to WRITE complete data");
      //error_handler(thread_close);
      
      status=-1;
      pthread_mutex_unlock(node->thread_mutex);
	goto exit;
      // exit(EXIT_FAILURE);
    }

    if (pthread_mutex_unlock(node->thread_mutex) != 0) {
      syslog(LOG_ERR, "ERROR: Failed to unlock mutex");
      status=-1;
	goto exit;
    }

    	        if ((memchr(buf, '\n', n_received)) != NULL)
    	        {
    	            packet_receive_complete = 1;
    	            break;
    	        }
    int i = 0;
    // or can you some standerd functions like memchr
    for (i = 0; i < n_received; i++) {
      if (buf[i] == '\n') {
        packet_receive_complete = 1;
        break;
      }
    }

    // If newline found, break out of the loop
    if (packet_receive_complete == 1) {
      break;
    }
  }
  #if (USE_AESD_CHAR_DEVICE == 0)	 
   close(file_fd);
   file_fd = open(DATA_FILE, O_RDONLY, S_IRUSR | S_IRGRP | S_IROTH);
   if (-1 == file_fd)
   {
      syslog(LOG_ERR, "Error opening %s file: %s", DATA_FILE, strerror(errno)); 
      status=-1;
	goto exit;
  }
  #endif
    	    int read_bytes = 0;
    	    int send_bytes = 0;
  data_reading:
    	    do
    	    {
    	        memset(buf, 0, BUFF_SIZE);
    	        read_bytes = read(file_fd, buf, BUFF_SIZE);
    	        if (read_bytes == -1)
    	        {
    	            	syslog(LOG_ERR, "ERROR: Failed to read from file");
   		    	status = -1;
              		goto exit;
            	}
            	if (read_bytes > 0)
            	{
            	    	send_bytes = send(node->client_socket_fd, buf, read_bytes, 0);
                	if (send_bytes != read_bytes)
                	{
                    		syslog(LOG_ERR, "ERROR: Failed to Send bytes to client");
                    		status = -1;
                    		goto exit;
                	}
                	status = 0;
            	}
            } while (read_bytes > 0);
  exit:    
     if (close(node->client_socket_fd) ==0)
    		{
    		    	syslog(LOG_INFO, "Closed connection from %s", ip_addr);
    		}
    if (file_fd != -1) {
      close(file_fd);
      syslog(LOG_INFO, "FILE closure: %d", file_fd);
    }
    if(status== -1)
    {
        node->my_thread_complete = false;
    }else{
        node->my_thread_complete = true;
    }
    return thread_node;
}
int main(int argc, char *argv[]) {
  int exit_status_flag = 0;

  struct addrinfo hints, *servinfo;
  socket_node_t *data_ptr = NULL;
  socket_node_t *data_ptr_temp = NULL;
  pthread_mutex_t thread_mutex = PTHREAD_MUTEX_INITIALIZER;

  SLIST_HEAD(socket_head, socket_node) head;
  SLIST_INIT(&head);
  while (exit_status_flag == 0) {
    openlog("aesdsocket", 0, LOG_USER);
        // Register signal handlers for SIGINT and SIGTERM
    	struct sigaction signal_actions;
    	sigemptyset(&signal_actions.sa_mask);
    	signal_actions.sa_flags = 0;
    	signal_actions.sa_handler = signal_handler;
    // Register signal handlers for SIGINT and SIGTERM
    	if (sigaction(SIGINT, &signal_actions, NULL) != 0)
	{
		syslog(LOG_ERR, "ERROR: Unable to register SIGINT signal handler");
		return -1;
	}
	if (sigaction(SIGTERM, &signal_actions, NULL) != 0)
	{
		syslog(LOG_ERR, "ERROR: Unable to register SIGTERM signal handler");
		return 0;
	}
        SLIST_HEAD(socket_head, socket_node) head;
    	SLIST_INIT(&head);

    // creates a socket for communication using IPv4 (AF_INET) and the TCP
    // protocol (SOCK_STREAM). The resulting file descriptor is stored in
    // socket_fd.
    socket_fd = socket(AF_INET, SOCK_STREAM, 0);
    // checks error condition for case of socket creation.
    if (socket_fd == -1) {
      syslog(LOG_ERR, "ERROR: socket() failed ");
      return -1;
      exit_status_flag = 1;
      break;
    }
    // pecifies that the address family is unspecified, allowing getaddrinfo to
    // return both IPv4 and IPv6 addresses. Indicates that the socket type is
    // streaming (TCP).
    //  Sets the AI_PASSIVE flag, allowing the resulting address to be used in a
    //  call to bind() for a server socket.
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE; // use my IP

    // Retrieves address information for the socket and Checks if getaddrinfo
    // failed to recover address information.
    if ((getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
      syslog(LOG_ERR, "ERROR: getaddrinfo() didnt recover address");
      exit_status_flag = 1;
      status=-1;
      break;
    }

    // This line sets the SO_REUSEADDR socket option, allowing the reuse of
    // local addresses. and Checks if setsockopt fails to set the SO_REUSEADDR
    // option
    int reusage = 1;
    if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reusage,
                   sizeof(int)) == -1) {
      syslog(LOG_ERR, "ERROR: SETSOCKOPT() -Failure");
      freeaddrinfo(servinfo);
      error_handler(Socket_created);
      status =-1;
      exit_status_flag = 1;
      break;
    }

    // Associates the socket with a specific address retrieved above from
    // getaddrinfo.
    if (bind(socket_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
      syslog(LOG_ERR, "ERROR: BIND() - Failure");
      // Frees the memory allocated for address information, as it is no longer
      // needed.
      freeaddrinfo(servinfo);
      error_handler(Socket_created);
      status =-1;
      exit_status_flag = 1;
      break;
    }
    freeaddrinfo(servinfo); // all done with this structure

    // Marks the socket as passive, ready to accept incoming connections with a
    // backlog queue size of 10.
    // Checks if listen fails to mark the socket as passive
    if (listen(socket_fd, 10) == -1) {
      syslog(LOG_ERR, "ERROR: LISTEN() -Failure");
      error_handler(Socket_created);
      exit_status_flag = 1;
      break;
    }

    if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
      pid_t pid;
      int i = 0;

      /* create new process If parent, log and exit successfully*/
      pid = fork();
      if (pid == -1) {
        syslog(LOG_ERR, "ERROR: FORK failed");
        exit_status_flag = 1;
        break;

      } else if (pid != 0) {
        syslog(LOG_INFO, "INFO- Parent");
        exit(EXIT_SUCCESS);
        // return 0;
      }
      // Child process continues here
      syslog(LOG_INFO, "INFO- Child");
      // Create a new session for the child process
      if (setsid() == -1) {
        syslog(LOG_ERR, "ERROR: SESSION FAIL");
        exit_status_flag = 1;
        break;
      }
      // Change the current working directory to the root directory
      if (chdir("/") == -1) {
        syslog(LOG_ERR, "ERROR: CHDIR FAIL");
        exit_status_flag = 1;
        break;
      }
      // Close all file descriptors except 0, 1, and 2
      for (i = 0; i < 3; i++) {
        close(i);
      }
      /* redirect fd's 0,1,2 to /dev/null */
      int fd = open("/dev/null", O_RDWR); /* stdin */
      dup(0);                             /* stdout */
      dup(0);                             /* stderror */
      close(fd);

      /* do its daemon thing... */
    }

#if (USE_AESD_CHAR_DEVICE == 0)	
    // Node for timestamp thread
    data_ptr = (socket_node_t *)malloc(sizeof(socket_node_t));
    if (data_ptr == NULL) {
      syslog(LOG_ERR, "ERROR: Failed to malloc");
      exit_status_flag = 1;
      break;
    }

    data_ptr->my_thread_complete = false;
    data_ptr->thread_mutex = &thread_mutex;
    // Thread for timestamp
    if (pthread_create(&data_ptr->my_thread_id, NULL, timestamp_thread,
                       data_ptr) != 0) {
      syslog(LOG_ERR, "ERROR: Failed to Create timer thread");
      free(data_ptr);
      data_ptr = NULL;
      exit_status_flag = 1;
      break;
    }
    SLIST_INSERT_HEAD(&head, data_ptr, node_next);
#endif

    while (transfer_exit != 1) {
      // Declares a variable to store the size of the client's address
      // structure.
      struct sockaddr_in client_addr;
      socklen_t client_len = sizeof(client_addr);
      // Accepts an incoming connection, obtaining a new socket file descriptor
      // specifically for that connection.
      client_socket_fd =
          accept(socket_fd, (struct sockaddr *)&client_addr, &client_len);

      if (client_socket_fd == -1) {
        syslog(LOG_ERR, "ERROR: Failed to ACCEPT SOCKET");
        //error_handler(file_work);
        exit_status_flag = 1;
        break;
      }
      // Converts the client's IP address from binary to a human-readable
      // string. simple inversion of gethostbyname concept.
      if (NULL == inet_ntop(AF_INET,
                            get_in_addr((struct sockaddr *)&client_addr),
                            ip_addr, sizeof(ip_addr))) {
        syslog(LOG_ERR, "ERROR: Failed to OBTAIN IP");
        //error_handler(file_work);
        exit_status_flag = 1;
        break;
      }
      syslog(LOG_DEBUG, "Accepted connection from %s", ip_addr);

      // Creating socket node for each connection
      data_ptr = (socket_node_t *)malloc(sizeof(socket_node_t));
      if (data_ptr == NULL) {
        syslog(LOG_ERR, "ERROR: Failed to malloc");
        //error_handler(file_work);
        status =-1;
        exit_status_flag = 1;
        break;
      }

      data_ptr->client_socket_fd = client_socket_fd;
      data_ptr->my_thread_complete = false;
      data_ptr->thread_mutex = &thread_mutex;
      // Create thread for each connection
      if (0 != pthread_create(&data_ptr->my_thread_id, NULL, data_thread,
                              data_ptr)) {
        syslog(LOG_ERR, "ERROR: Failed to create connection thread");
        free(data_ptr);
        data_ptr = NULL;
        //error_handler(file_work);
        status =-1;
        exit_status_flag = 1;
        break;
      }
      SLIST_INSERT_HEAD(&head, data_ptr, node_next);

      // If thread exited, join thread and remove from linkedlist
      data_ptr = NULL;
      SLIST_FOREACH_SAFE(data_ptr, &head, node_next, data_ptr_temp) {
        if (data_ptr->my_thread_complete == true) {
          syslog(LOG_INFO, "Thread ID joined is: %ld", data_ptr->my_thread_id);
          pthread_join(data_ptr->my_thread_id, NULL);
          SLIST_REMOVE(&head, data_ptr, socket_node, node_next);
          free(data_ptr);
          data_ptr = NULL;
          exit_status_flag = 1;
          break;
          //goto exit;
        }
      }
    }
    //return 0;
  }

  //exit:
  error_handler(file_work);
  //pthread_mutex_destroy(&thread_mutex);
  while (!SLIST_EMPTY(&head)) {
    data_ptr = SLIST_FIRST(&head);
    SLIST_REMOVE_HEAD(&head, node_next);
    pthread_join(data_ptr->my_thread_id, NULL);
    free(data_ptr);
    data_ptr = NULL;
  }
  pthread_mutex_destroy(&thread_mutex);
  printf("EXITING PROCESS\n");
  return status;
}
