#!/bin/bash

# Check if the number of arguments is correct
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <filesdir> <searchstr>"
    exit 1
fi

# Assign arguments to variables
filesdir="$1"
searchstr="$2"

# Check if the given directory path exists
if [ ! -d "$filesdir" ]; then
    echo "Error: '$filesdir' is not a directory."
    exit 1
fi

# Count the number of files in the specified directory
file_count=$(find "$filesdir" -type f | wc -l)
# Count the number of files with the  matching lines of the specified string.
match_count=$(grep -r "$searchstr" "$filesdir" | wc -l)

# Display the results to the user
echo "The number of files are $file_count and the number of matching lines are $match_count"

# Exit the script with a success status
exit 0
