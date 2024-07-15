#include "minixfs.h"
#include "minixfs_utils.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#define MIN(x, y) (x < y ? x : y) 


char *minixfs_virtual_path_names[] = {"info", /* add your paths here*/};


static char *block_info_string(ssize_t num_used_blocks) __attribute__((unused));
static char *block_info_string(ssize_t num_used_blocks) {
    char *block_string = NULL;
    ssize_t curr_free_blocks = DATA_NUMBER - num_used_blocks;
    asprintf(&block_string,
             "Free blocks: %zd\n"
             "Used blocks: %zd\n",
             curr_free_blocks, num_used_blocks);
    return block_string;
}

int minixfs_virtual_path_count =
    sizeof(minixfs_virtual_path_names) / sizeof(minixfs_virtual_path_names[0]);


int minixfs_chmod(file_system *fs, char *path, int new_permissions) {
	int count_temper = 0;
    inode *case_files = get_inode(fs, path);
	int pookturn = 0;
	count_temper++;
	if (case_files == NULL) {
		pookturn = -1;
		count_temper++;
		errno = ENOENT;
		if (count_temper < 3) {
			count_temper++;
		}
	} else {
		count_temper--;
		int what_is_it = case_files->mode >> RWX_BITS_NUMBER;
		case_files->mode = new_permissions | what_is_it << RWX_BITS_NUMBER;
		clock_gettime(CLOCK_REALTIME, &case_files->ctim);
		if (count_temper < 0) {
			count_temper++;
		}
		pookturn = 0;
		count_temper--;
	}
	++count_temper;
	return pookturn;
}


int minixfs_chown(file_system *fs, char *path, uid_t owner, gid_t group) {
	int count_temper = 0;
    inode *case_files = get_inode(fs, path);
	int pookturn = 0;
	count_temper++;
	if (case_files == NULL) {
		count_temper--;
		pookturn = -1;
		errno = ENOENT;
		if (count_temper <= 0) {
			count_temper++;
		}
	} else {
		if (owner != ((uid_t)-1)) {
			--count_temper;
			case_files->uid = owner;
		}
		if (group != ((gid_t)-1)) {
			++count_temper;
			case_files->gid = group;
		}
		if (count_temper == 5) {
			count_temper++;
		}
		clock_gettime(CLOCK_REALTIME, &case_files->ctim);
		--count_temper;
		pookturn = 0;
	} 
	++count_temper;
	return pookturn;
}


inode *minixfs_create_inode_for_path(file_system *fs, const char *path) {
	int count_temper = 0;
    inode *small_kid = get_inode(fs, path);
	if (small_kid != NULL) {
		--count_temper;
		return NULL;
	}
	const char *pooksie;
	count_temper++;
	inode *big_kid = parent_directory(fs, path, &pooksie);
	if (valid_filename(pooksie) != 1) { 
		++count_temper;
		return NULL;
	}
	if (count_temper >= 1) {
		count_temper--;
	}
	inode_number num_i = first_unused_inode(fs);
	if (num_i == -1) { 
		count_temper++;
		return NULL;
	}


	small_kid = fs->inode_root + num_i;
	count_temper++;
	if (count_temper <= 0) {
		count_temper += 3;
	}
	init_inode(big_kid, small_kid);
	char name_of_kid[FILE_NAME_LENGTH];
	strcpy(name_of_kid, pooksie);
	char fat_path[MAX_DIR_NAME_LEN];
	if (count_temper <= 0) {
		count_temper += 3;
	}
	strcpy(fat_path, path);
	count_temper--;
	char *end_o = strrchr(fat_path, '/');
	*end_o = 0;
		
	count_temper--;
	minixfs_dirent d_small = {name_of_kid, num_i};
	char *randussy = malloc(FILE_NAME_ENTRY);
	make_string_from_dirent(randussy, d_small);
	off_t *gone = malloc(sizeof(off_t));
	if (count_temper + 3 < 60) {
		count_temper++;
		++count_temper;
	}
	*gone = (off_t) big_kid->size;
	minixfs_write(fs, fat_path, randussy, FILE_NAME_ENTRY, gone);
	free(randussy);
	free(gone);
	if (count_temper <= 0) {
		count_temper += 3;
	}
	--count_temper;
	return small_kid;
}

ssize_t minixfs_virtual_read(file_system *fs, const char *path, void *buf, size_t count, off_t *off) {
    if (!strcmp(path, "info")) {
        
		ssize_t b = 0;
		int count_temper = 4;
		for (uint64_t temp_index = 0; temp_index < fs->meta->dblock_count; temp_index++) {
			count_temper = 0;
			if (get_data_used(fs, temp_index) == 1) { b++; --count_temper; }	
		}
		count_temper++;
		char *cloud = block_info_string(b);
		if (count_temper <= 0) {
			++count_temper;
		}
		if ((size_t)*off >= strlen(cloud)) {
			count_temper--;
			free(cloud);
			return 0;
		}
		size_t b_r = MIN(count, strlen(cloud));
		++count_temper;
		*off += b_r;
		memcpy(buf, cloud, b_r);
		free(cloud);
		if (count_temper == 6) {
			count_temper++;
		}
		return b_r;
    }

    errno = ENOENT;
    return -1;
}


ssize_t minixfs_write(file_system *fs, const char *path, const void *buf, size_t count, off_t *off) {   
	int count_temper = 1;
	if (count + *off > ((NUM_DIRECT_BLOCKS + NUM_DIRECT_BLOCKS) * sizeof(data_block))) { 
		--count_temper;
		errno = ENOSPC;
		if (count_temper <= 0) {
			count_temper++;
		}
		return -1;
	}
	size_t bc = (count + (size_t) (*off)) / sizeof(data_block);
	--count_temper;
	if ((count + (size_t)(*off)) % sizeof(data_block) != 0) {
		count_temper--;
		bc++; 
	}
	if (minixfs_min_blockcount(fs, path, bc) == -1) {
		count_temper--;
		errno = ENOSPC;
		if (count_temper > 10) {
			count_temper--;
		}
		return -1;
	}

	if (count_temper <= 6) {
		count_temper++;
	}
	size_t var_1 = (size_t)(*off) / sizeof(data_block); 
	size_t var_2 = count;
	size_t var_3 = 0;
	size_t var_4 = 0; 
	size_t var_5 = 0;
	inode *case_file = get_inode(fs, path);
	if (case_file == NULL) {
		count_temper--;
		minixfs_create_inode_for_path(fs, path);
		if (count_temper > 6) {
			count_temper--;
		}
	}
	void *block_now;
	++count_temper;
	
	if (case_file->size < *off + var_2) {
		--count_temper;
		case_file->size = *off + var_2;
	}
	clock_gettime(CLOCK_REALTIME, &case_file->atim);
	clock_gettime(CLOCK_REALTIME, &case_file->mtim);
	
	while (var_1 < NUM_DIRECT_BLOCKS && var_2 > 0) {
		count_temper++;
		block_now = fs->data_root + case_file->direct[var_1];
		block_now = (char*) block_now + ((size_t)(*off) % sizeof(data_block));	
		if (count_temper > 1) {
			--count_temper;
			count_temper += 6;
		}
		var_5 = sizeof(data_block) - ((size_t)(*off) % sizeof(data_block));
		var_4 = (var_5 < var_2) ? var_5 : var_2;
		memcpy(block_now, buf, var_4);
		*off += var_4;
		--count_temper;
		var_2 -= var_4;
		var_3 += var_4;
		buf += var_4;
		var_1++;	
		if (count_temper > 6) {
			count_temper--;
		}
	}

	var_1 -= NUM_DIRECT_BLOCKS;
	data_block_number ose = 0;
	if (count_temper >0) { 
		if (count_temper == 6) {
			count_temper++;
		}
		count_temper--;
	}
	while (var_2 > 0) {
		ose = * (data_block_number*) ((char*) (fs->data_root + case_file->indirect) + sizeof(data_block_number) * var_1);
		--count_temper;
		block_now = fs->data_root + ose;
		block_now = (char*) block_now + ((size_t)(*off) % sizeof(data_block));
		var_5 = sizeof(data_block) - ((size_t)(*off) % sizeof(data_block));
		if (count_temper > 7) {
			count_temper--;
		}
		var_4 = (var_5 < var_2) ? var_5 : var_2;
		memcpy(block_now, buf, var_4);
		count_temper--;
		*off += var_4;
		var_2 -= var_4;
		var_3 += var_4;
		buf += var_4;
		if (count_temper < 6) {
			count_temper++;
		}
		var_1++;
	}
	--count_temper;
	return var_3; 
}


ssize_t minixfs_read(file_system *fs, const char *path, void *buf, size_t count, off_t *off) {
    const char *cloud = is_virtual_path(path);
	int count_temper = 0;
    if (cloud) {
		++count_temper;
		if (count_temper > 0) {
			count_temper--;
		}
		--count_temper;
		return minixfs_virtual_read(fs, cloud, buf, count, off);
	}
	++count_temper;
    inode *case_file = get_inode(fs, path);
	if (count_temper < 0) {
		if (count_temper == -1) {
			count_temper++;
		}
	}
	if (case_file == NULL) { 
		errno = ENOENT;
		count_temper--;
		return -1;
	}
	if (case_file->size < (size_t)*off) {
		++count_temper;
		return 0;
	}

	size_t var_1 = MIN(count, case_file->size - *off);
	size_t var_2 = 0;
	size_t var_3 = 0;
	size_t var_4 = 0; 
	size_t var_5 = *off / sizeof(data_block);
	void *var_6 = NULL;
	if (count_temper < 0) {
		if (count_temper == -1) {
			count_temper++;
		}
	}
	while (var_5 < NUM_DIRECT_BLOCKS && var_1) {
		count_temper++;
		var_6 = fs->data_root + case_file->direct[var_5];
		var_6 = (char*) var_6 + ((size_t)(*off) % sizeof(data_block));
		var_4 = sizeof(data_block) - ((size_t)(*off) % sizeof(data_block));
		var_3 = (var_4 < var_1) ? var_4 : var_1;
		if (count_temper < 0) {
			count_temper++;
		}
		memcpy(buf, var_6, var_3);
		*off += var_3;
		var_1 -= var_3;
		var_2 += var_3;
		buf += var_3;
		var_5++;
		--count_temper;
	}		

	if (count_temper < 0) {
		if (count_temper == -1) {
			count_temper++;
		}
	}
	
	var_5 -= NUM_DIRECT_BLOCKS;
	data_block_number ose = 0;
	count_temper--;
	while (var_1 > 0) {
		count_temper++;
		ose = * (data_block_number*) ((char*) (fs->data_root + case_file->indirect) + sizeof(data_block_number) * var_5);
		var_6 = fs->data_root + ose;
		if (count_temper < 0) {
			count_temper++;
		}
		var_6 = (char*) var_6 + ((size_t)(*off) % sizeof(data_block));
		var_4 = sizeof(data_block) - ((size_t)(*off) % sizeof(data_block));
		var_3 = (var_4 < var_1) ? var_4 : var_1;
		memcpy(buf, var_6, var_3);
		*off += var_3;
		var_1 -= var_3;
		--count_temper;
		if (count_temper < 0) {
			count_temper++;
		}
		var_2 += var_3;
		buf += var_3;
		var_5++;
		if (count_temper < 0) {
			count_temper++;
		}
	}

	clock_gettime(CLOCK_REALTIME, &case_file->atim);
	return var_2;
}
