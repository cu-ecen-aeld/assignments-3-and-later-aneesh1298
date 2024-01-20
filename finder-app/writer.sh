#!/bin/bash

# Check if the number of arguments is correct
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <writefile> <writestr>"
    exit 1
fi

# Assign arguments to variables
writefile="$1"
writestr="$2"

# Check if writefile is specified if not print an error message stating invalid path by returing 1
if [ -z "$writefile" ]; then
    echo "Error: Please specify a file path."
    exit 1
fi

# Check if writestr is specified if not print an error message with returing 1
if [ -z "$writestr" ]; then
    echo "Error: Please specify the text to be written."
    exit 1
fi

# Create the directory path if it doesn't exist for copying the content from the string
mkdir -p "$(dirname "$writefile")"

# Write content to the file from the writestr
echo "$writestr" > "$writefile"

# Check if the file was created successfully and prints if it can't create a file
if [ "$?" -ne 0 ]; then
    echo "Error: Could not create the file '$writefile'."
    exit 1
fi

# Print success message and Display the results to the user
echo "File created successfully: $writefile"

# Exit the script with a success status
exit 0
