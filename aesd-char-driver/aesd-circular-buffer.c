/**
 * @file aesd-circular-buffer.c
 * @brief Functions and data related to a circular buffer imlementation
 *
 * @author Dan Walkes
 * @date 2020-03-01
 * @copyright Copyright (c) 2020
 *
 */

#ifdef __KERNEL__
#include <linux/string.h>
#else
#include <string.h>
#endif

#include "aesd-circular-buffer.h"

#define MAX_NUMBER 9

/**
 * @param buffer the buffer to search for corresponding offset.  Any necessary locking must be performed by caller.
 * @param char_offset the position to search for in the buffer list, describing the zero referenced
 *      character index if all buffer strings were concatenated end to end
 * @param entry_offset_byte_rtn is a pointer specifying a location to store the byte of the returned aesd_buffer_entry
 *      buffptr member corresponding to char_offset.  This value is only set when a matching char_offset is found
 *      in aesd_buffer.
 * @return the struct aesd_buffer_entry structure representing the position described by char_offset, or
 * NULL if this position is not available in the buffer (not enough data is written).
 */
struct aesd_buffer_entry *aesd_circular_buffer_find_entry_offset_for_fpos(struct aesd_circular_buffer *buffer,
            size_t char_offset, size_t *entry_offset_byte_rtn )
{
    /**
    * TODO: implement per description
    */
    
    if(buffer==NULL || char_offset<0 || entry_offset_byte_rtn == NULL)
    {
    	return NULL;
    }
    struct aesd_buffer_entry *return_entry = NULL;
    uint8_t current_entry = buffer->out_offs;
    uint8_t entries_count = 0;
    if(buffer->full==1)
    {
    	entries_count= AESDCHAR_MAX_WRITE_OPERATIONS_SUPPORTED;
    }
    else
    {
    	entries_count= buffer->in_offs - buffer->out_offs;
    }
    if(entries_count==0)
    {
    	return NULL;
    }
    while(entries_count--)
    {
    	return_entry= &buffer->entry[current_entry];
    	if(char_offset< buffer->entry[current_entry].size)
    	{
    		*entry_offset_byte_rtn= char_offset;
    		return return_entry;
    	} 
    	char_offset= char_offset - (buffer->entry[current_entry].size);
    	// special case that might occur when we are done with entries and next element to be send is given by char_offset
    	if(char_offset==0 && entries_count==0)
    	{
    	return NULL;
    	}
    	if(current_entry==MAX_NUMBER)
    	{
    		current_entry=0;
    	}
    	else
    	{
    		current_entry++;
    	}
    }
    
    return return_entry;
}

/**
* Adds entry @param add_entry to @param buffer in the location specified in buffer->in_offs.
* If the buffer was already full, overwrites the oldest entry and advances buffer->out_offs to the
* new start location.
* Any necessary locking must be handled by the caller
* Any memory referenced in @param add_entry must be allocated by and/or must have a lifetime managed by the caller.
*/
const char* aesd_circular_buffer_add_entry(struct aesd_circular_buffer *buffer, const struct aesd_buffer_entry *add_entry)
{
    /**
    * TODO: implement per description
    */
    const char* free_ptr = NULL;
    if(buffer==NULL || add_entry==NULL)
    {
    	return NULL;
    }
    // Bringing this condition from down as commented below.
    if (buffer->full)
    {
        free_ptr = buffer->entry[buffer->in_offs].buffptr;
        if (buffer->out_offs >= MAX_NUMBER)
        {
            buffer->out_offs = 0;
        }
        else
        {
            buffer->out_offs++;
        }
    }
    memcpy(&buffer->entry[buffer->in_offs], add_entry, sizeof(struct aesd_buffer_entry));
    // here we are considering movement of out_offs when we have a buffer which is already full and filling new details.
    if(buffer->in_offs==MAX_NUMBER)
    {
    	//if(buffer->full==1)
    	//{
    		//buffer->out_offs= buffer->out_offs-  MAX_NUMBER;
    	//}
    	buffer->in_offs= buffer->in_offs-MAX_NUMBER;
        //buffer->full = true;
    }
    else
    {
 	(buffer->in_offs)++;
    	//if(buffer->full ==1)
    	//{
    		//(buffer->out_offs)++;
    	//}   
    }
    
    if (buffer->in_offs == buffer->out_offs)
    {
        buffer->full = true;
    }
    else
    {
        buffer->full = false;
    }
    return free_buffptr;
    
}

/**
* Initializes the circular buffer described by @param buffer to an empty struct
*/
void aesd_circular_buffer_init(struct aesd_circular_buffer *buffer)
{
    memset(buffer,0,sizeof(struct aesd_circular_buffer));
}
