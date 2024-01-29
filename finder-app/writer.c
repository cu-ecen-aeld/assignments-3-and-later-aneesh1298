#include <stdio.h>
#include <stdlib.h>
#include <syslog.h>

void writeToFile(const char *filename, const char *content) {
    FILE *file = fopen(filename, "w");
    if (file == NULL) {
        syslog(LOG_ERR, "Error opening file: %s", filename);
        exit(EXIT_FAILURE);
    }

    fprintf(file, "%s\n", content);
    fclose(file);
}

int main(int argc, char *argv[]) {
    // Open syslog connection with LOG_USER facility
    openlog(NULL, 0, LOG_USER);

    // Check if the correct number of arguments is provided
    //if (argc != 3) {
        //syslog(LOG_ERR, "Usage: %s <file_path> <text_to_write>", argv[0]);
      //  exit(EXIT_FAILURE);
    //}

    // Assign provided values to variables
    const char *filename = argv[1];
    const char *content = argv[2];

    if(argc !=3)
	  {
		  syslog(LOG_ERR, "Usage: %s <file_path> %s", argv[0],content);
		  exit(EXIT_FAILURE);
          }

    // Write to file and log success message
    writeToFile(filename, content);
    syslog(LOG_DEBUG, "Writing '%s' to '%s'", content, filename);

    // Close syslog
    closelog();

    return 0;
}
