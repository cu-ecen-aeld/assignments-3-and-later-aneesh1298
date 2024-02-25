#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <netdb.h> //has the struct addrinfo variable here
#include <netinet/in.h>
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
#include <unistd.h>

#define PORT "9000"
#define DATA_FILE "/var/tmp/aesdsocketdata"
#define BUF_SIZE 1024

int socket_fd = 0;
int client_socket_fd = 0;
int file_fd = 0;
int transfer_exit = 0;
typedef enum status {
  Socket_created,
  client_socket,
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
    syslog(LOG_INFO, "CLOSE socket_fd: %d", socket_fd);
  }
  // Close socket_fd and client_socket_fd, and log closure messages if the error
  // occurred at the client_socket stage.
  else if (transfer_status == client_socket) {
    close(socket_fd);
    syslog(LOG_INFO, "CLOSE socket_fd: %d", socket_fd);
    close(client_socket_fd);
    syslog(LOG_INFO, "CLOSE client_socket_fd: %d", client_socket_fd);
  }
  // Close socket_fd, client_socket_fd, and file_fd, and log closure messages if
  // the error occurred at the transfer_complete stage.
  else {
    close(socket_fd);
    syslog(LOG_INFO, "CLOSE socket_fd: %d", socket_fd);
    close(client_socket_fd);
    syslog(LOG_INFO, "CLOSE client_socket_fd: %d", client_socket_fd);
    close(file_fd);
    syslog(LOG_INFO, "FILE closure: %d", file_fd);
  }
  // Close the syslog and remove the temporary data file.
  closelog();
  remove(DATA_FILE);
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
    exit(EXIT_SUCCESS);
  }
}

int main(int argc, char *argv[]) {
  struct addrinfo hints, *servinfo;
  // Open the syslog with LOG_USER facility
  openlog("aesdsocket", 0, LOG_USER);
  // Register signal handlers for SIGINT and SIGTERM
  if (SIG_ERR == signal(SIGINT, signal_handler)) {
    syslog(LOG_ERR, "ERROR: signal() failed for SIGINT");
    // exit(EXIT_FAILURE);
  }

  if (SIG_ERR == signal(SIGTERM, signal_handler)) {
    syslog(LOG_ERR, "ERROR: signal() failed for SIGTERM");
    // exit(EXIT_FAILURE);
  }

  // creates a socket for communication using IPv4 (AF_INET) and the TCP
  // protocol (SOCK_STREAM). The resulting file descriptor is stored in
  // socket_fd.
  socket_fd = socket(AF_INET, SOCK_STREAM, 0);
  // checks error condition for case of socket creation.
  if (socket_fd == -1) {
    syslog(LOG_ERR, "ERROR: socket() failed ");
    exit(EXIT_FAILURE);
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
    exit(EXIT_FAILURE);
  }

  // This line sets the SO_REUSEADDR socket option, allowing the reuse of local
  // addresses. and Checks if setsockopt fails to set the SO_REUSEADDR option
  int reusage = 1;
  if (setsockopt(socket_fd, SOL_SOCKET, SO_REUSEADDR, &reusage, sizeof(int)) ==
      -1) {
    syslog(LOG_ERR, "ERROR: SETSOCKOPT() -Failure");
    freeaddrinfo(servinfo);
    error_handler(Socket_created);
    exit(EXIT_FAILURE);
  }

  // Associates the socket with a specific address retrieved above from
  // getaddrinfo.
  if (bind(socket_fd, servinfo->ai_addr, servinfo->ai_addrlen) == -1) {
    syslog(LOG_ERR, "ERROR: BIND() - Failure");
    // Frees the memory allocated for address information, as it is no longer
    // needed.
    freeaddrinfo(servinfo);
    error_handler(Socket_created);
    exit(EXIT_FAILURE);
  }
  freeaddrinfo(servinfo); // all done with this structure

  // Marks the socket as passive, ready to accept incoming connections with a
  // backlog queue size of 10.
  // Checks if listen fails to mark the socket as passive
  if (listen(socket_fd, 10) == -1) {
    syslog(LOG_ERR, "ERROR: LISTEN() -Failure");
    error_handler(Socket_created);
    exit(EXIT_FAILURE);
  }

  if ((argc == 2) && (strcmp(argv[1], "-d") == 0)) {
    pid_t pid;
    int i = 0;

    /* create new process If parent, log and exit successfully*/
    pid = fork();
    if (pid == -1) {
      syslog(LOG_ERR, "ERROR: FORK failed");
      exit(EXIT_FAILURE);
    } else if (pid != 0) {
      syslog(LOG_INFO, "INFO- Parent");
      exit(EXIT_SUCCESS);
    }
    // Child process continues here
    syslog(LOG_INFO, "INFO- Child");
    // Create a new session for the child process
    if (setsid() == -1) {
      syslog(LOG_ERR, "ERROR: SESSION FAIL");
      exit(EXIT_FAILURE);
    }
    // Change the current working directory to the root directory
    if (chdir("/") == -1) {
      syslog(LOG_ERR, "ERROR: CHDIR FAIL");
      exit(EXIT_FAILURE);
    }
    // Close all file descriptors except 0, 1, and 2
    for (i = 0; i < 3; i++) {
      close(i);
    }
    /* redirect fd's 0,1,2 to /dev/null */
    int fd = open("/dev/null", O_RDWR); /* stdin */
    //dup(0);                             /* stdout */
    //dup(0);                             /* stderror */
    		if (fd == -1)
        	{
            		syslog(LOG_PERROR, "open:%s\n", strerror(errno));
            		close(fd);
            		error_handler(Socket_created);
            		exit(EXIT_FAILURE);
            		//close_n_exit(EXIT_FAILURE);       
        	}
        	if (dup2(fd, STDIN_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		error_handler(Socket_created);
            		exit(EXIT_FAILURE);   
        	}
        	if (dup2(fd, STDOUT_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		error_handler(Socket_created);
            		exit(EXIT_FAILURE);    
        	}
        	if (dup2(fd, STDERR_FILENO)  == -1)
        	{
            		syslog(LOG_PERROR, "dup2:%s\n", strerror(errno));
            		close(fd);
            		error_handler(Socket_created);
            		exit(EXIT_FAILURE);   
        	}
        	close(fd);
    //close(fd);

    /* do its daemon thing... */
  }

  while (transfer_exit != 1) {
    // Declares a variable to store the size of the client's address structure.
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    // Accepts an incoming connection, obtaining a new socket file descriptor
    // specifically for that connection.
    client_socket_fd =
        accept(socket_fd, (struct sockaddr *)&client_addr, &client_len);

    if (client_socket_fd == -1) {
      syslog(LOG_ERR, "ERROR: Failed to ACCEPT SOCKET");
      error_handler(file_work);
      exit(EXIT_FAILURE);
    }
    // Converts the client's IP address from binary to a human-readable string.
    // simple inversion of gethostbyname concept.
    if (NULL == inet_ntop(AF_INET, get_in_addr((struct sockaddr *)&client_addr),
                          ip_addr, sizeof(ip_addr))) {
      syslog(LOG_ERR, "ERROR: Failed to OBTAIN IP");
      error_handler(file_work);
      exit(EXIT_FAILURE);
    }
    syslog(LOG_DEBUG, "Accepted connection from %s", ip_addr);
    char buf[BUF_SIZE];
    int packet_receive_complete = 0;
    // Create file to push data to /var/tmp/aesdsocketdata
    file_fd = open(DATA_FILE, O_CREAT | O_RDWR | O_APPEND, 0744);
    if (file_fd == -1) {
      syslog(LOG_ERR,
             "ERROR: Failed to  OPEN the FILE at /var/temp/aesdsocketdata");
      error_handler(Socket_created);
      exit(EXIT_FAILURE);
    }

    while (1) {
      // bzero(buf, BUF_SIZE);
      memset(buf, 0, BUF_SIZE);
      int n_received = recv(client_socket_fd, buf, 1024, 0);
      if (n_received == -1) {
        syslog(LOG_ERR, "ERROR: Failed to RECEIVE data");
        error_handler(file_work);
        exit(EXIT_FAILURE);
      }

      int n_written = write(file_fd, buf, n_received);
      if ((n_written != n_received)) {
        syslog(LOG_ERR, "ERROR: Failed to WRITE complete data");
        error_handler(file_work);
        exit(EXIT_FAILURE);
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
    struct stat file_info;
    fstat(file_fd, &file_info);
    int file_size = file_info.st_size;
    int cursor_set = lseek(file_fd, 0, SEEK_SET);
    if (cursor_set == -1) {
      syslog(LOG_ERR, "ERROR: Failed to SEEK cursor to start");
      error_handler(file_work);
      exit(EXIT_FAILURE);
    }
    int byte_transfer_size = 1024;
    for (int cumulatives_bytes_transferred = 0;
         file_size >= cumulatives_bytes_transferred;
         cumulatives_bytes_transferred += byte_transfer_size) {
      // bzero(buf, 1024);
      memset(buf, 0, 1024);
      if (file_size - cumulatives_bytes_transferred < 1024) {
        byte_transfer_size = file_size - cumulatives_bytes_transferred;
      }
      int bytes_read = read(file_fd, buf, 1024);
      if (bytes_read == -1) {
        syslog(LOG_ERR, "ERROR: Failed to READ data");
        error_handler(file_work);
        exit(EXIT_FAILURE);
      }
      syslog(LOG_INFO,
             "Sent %d bytes of data in total till now from %d in total",
             bytes_read, file_size);
      if (bytes_read > 0) {
        int bytes_sent = send(client_socket_fd, buf, bytes_read, 0);
        if (bytes_sent != bytes_read) {
          syslog(LOG_ERR, "ERROR: Failed to SEND data");
          error_handler(file_work);
          exit(EXIT_FAILURE);
        }
      }
      if (byte_transfer_size < 1024) {
        printf("file transfer complete from  server\n");
        syslog(LOG_INFO, "file transfer complete from  server");
        // No other possibility to close than success
        int file_closure = close(file_fd);
        if (file_closure == 0) {
          syslog(LOG_INFO, "CLOSED file after transfer complete");
          syslog(LOG_INFO, "Closed connection from %s", ip_addr);
        }
        break;
      }
    }
  }
}
