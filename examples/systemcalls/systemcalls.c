#include "systemcalls.h"
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <stdarg.h>
#include <stdbool.h>
#include <fcntl.h>

/**
 * @param cmd the command to execute with system()
 * @return true if the command in @param cmd was executed
 *   successfully using the system() call, false if an error occurred,
 *   either in invocation of the system() call, or if a non-zero return
 *   value was returned by the command issued in @param cmd.
*/
bool do_system(const char *cmd)
{
    // Check if the command is NULL
    if (cmd == NULL) {
        // If the shell /bin/sh is available, return true; otherwise, return false
        return (system(NULL) != 0);
    }
/*
 * TODO  add your code here
 *  Call the system() function with the command set in the cmd
 *   and return a boolean true if the system() call completed with success
 *   or false() if it returned a failure
*/
    // Call the system() function with the provided command
    int result = system(cmd);

    // Check if the system() call was successful
    if (result == 0)
    {
        return true;  // Success
    }
    else
    {
        // Print an error message if system() failed
        perror("system");
        return false;  // Failure
    }

   // return true;
}

/**
* @param count -The numbers of variables passed to the function. The variables are command to execute.
*   followed by arguments to pass to the command
*   Since exec() does not perform path expansion, the command to execute needs
*   to be an absolute path.
* @param ... - A list of 1 or more arguments after the @param count argument.
*   The first is always the full path to the command to execute with execv()
*   The remaining arguments are a list of arguments to pass to the command in execv()
* @return true if the command @param ... with arguments @param arguments were executed successfully
*   using the execv() call, false if an error occurred, either in invocation of the
*   fork, waitpid, or execv() command, or if a non-zero return value was returned
*   by the command issued in @param arguments with the specified arguments.
*/

bool do_exec(int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];

    // To mention that there is a need of more than or equal to 1 command after count parameter 
    if(count <=1)
    {
	    return false;
    }

   va_end(args);

/*
 * TODO:
 *   Execute a system command by calling fork, execv(),
 *   and wait instead of system (see LSP page 161).
 *   Use the command[0] as the full path to the command to execute
 *   (first argument to execv), and use the remaining arguments
 *   as second argument to the execv() command.
 *
*/
    // Fork a child process
    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return false; // Fork failed
    }
    else if (pid == 0)
    {
        // Child process
        execv(command[0], command);
        perror("execv"); // This line is reached only if execv fails
        exit(EXIT_FAILURE);
    }
    else
    {
        // Parent process
        int status;
        if (waitpid(pid, &status, 0) == -1)
        {
            perror("waitpid");
            return false; // waitpid failed
        }

        // Check if the child process terminated successfully
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        {
            return true; // Executed successfully
        }
        else
        {
            return false; // Command returned a non-zero exit status
        }
    }
}
/**
* @param outputfile - The full path to the file to write with command output.
*   This file will be closed at completion of the function call.
* All other parameters, see do_exec above
*/
bool do_exec_redirect(const char *outputfile, int count, ...)
{
    va_list args;
    va_start(args, count);
    char * command[count+1];
    int i;
    for(i=0; i<count; i++)
    {
        command[i] = va_arg(args, char *);
    }
    command[count] = NULL;
    // this line is to avoid a compile warning before your implementation is complete
    // and may be removed
    command[count] = command[count];


/*
 * TODO
 *   Call execv, but first using https://stackoverflow.com/a/13784315/1446624 as a refernce,
 *   redirect standard out to a file specified by outputfile.
 *   The rest of the behaviour is same as do_exec()
 *
*/

    va_end(args);
// Fork a child process
    pid_t pid = fork();

    if (pid == -1)
    {
        perror("fork");
        return false; // Fork failed
    }
    else if (pid == 0)
    {
        // Child process

        // Open the output file for writing (creating if it doesn't exist, truncating otherwise)
        int output_fd = open(outputfile, O_WRONLY | O_CREAT | O_TRUNC, 0666);

        if (output_fd == -1)
        {
            perror("open");
            exit(EXIT_FAILURE);
        }

        // Redirect standard output to the output file
        if (dup2(output_fd, STDOUT_FILENO) == -1)
        {
            perror("dup2");
            close(output_fd);
            exit(EXIT_FAILURE);
        }

        // Close the duplicated file descriptor
        close(output_fd);

        // Execute the command
        execv(command[0], command);

        perror("execv"); // This line is reached only if execv fails
        exit(EXIT_FAILURE);
    }
    else
    {
        // Parent process
        int status;
        if (waitpid(pid, &status, 0) == -1)
        {
            perror("waitpid");
            return false; // waitpid failed
        }

        // Check if the child process terminated successfully
        if (WIFEXITED(status) && WEXITSTATUS(status) == 0)
        {
            return true; // Executed successfully
        }
        else
        {
            return false; // Command returned a non-zero exit status
        }
    }
   // return true;
}
