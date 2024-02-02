#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bf.h"
#include "hp_file.h"
#include "record.h"


#define CALL_BF(call)           \
{                               \
	BF_ErrorCode code = call;   \
	if (code != BF_OK) {        \
		BF_PrintError(code);    \
		return HP_ERROR;        \
	}                           \
}                               \


int HP_CreateFile(char *fileName) {
    BF_ErrorCode result = BF_CreateFile(fileName);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    int file_descriptor;
    result = BF_OpenFile(fileName, &file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block *block;
    BF_Block_Init(&block);
    result = BF_AllocateBlock(file_descriptor, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    void *data = BF_Block_GetData(block);

    HP_info hp_info;
    hp_info.file_type = HP_FILE;
    hp_info.file_descriptor = file_descriptor;
    hp_info.block_id = 0;
    hp_info.last_block = 0;
    hp_info.max_records = (BF_BLOCK_SIZE - sizeof(HP_block_info)) / (sizeof(Record));

    memcpy(data, &hp_info, sizeof(HP_info));

    BF_Block_SetDirty(block);

    result = BF_UnpinBlock(block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_Destroy(&block);

    result = BF_CloseFile(file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    return 0;
}

HP_info* HP_OpenFile(char *fileName) {
    int file_descriptor;
    BF_ErrorCode result = BF_OpenFile(fileName, &file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return NULL;
    }

    BF_Block *block;
    BF_Block_Init(&block);
    result = BF_GetBlock(file_descriptor, 0, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return NULL;
    }

    void *data = BF_Block_GetData(block);
    HP_info* hp_info = malloc(sizeof(HP_info));
    hp_info = data;
    if (hp_info->file_type != HP_FILE)
        return NULL;

    BF_Block_Destroy(&block);

    return hp_info;
}

int HP_CloseFile(HP_info* hp_info) {
    int file_descriptor = hp_info->file_descriptor;

    BF_Block *block;
  	BF_Block_Init(&block);
    BF_ErrorCode result = BF_GetBlock(file_descriptor, 0, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_SetDirty(block);

    result = BF_UnpinBlock(block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_Destroy(&block);

    result = BF_CloseFile(file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    free(hp_info);

    return 0;
}

int HP_InsertEntry(HP_info* hp_info, Record record) {
    int file_descriptor = hp_info->file_descriptor;

    int last_block = hp_info->last_block;
    int max_records = hp_info->max_records;  

    BF_Block *block;
    BF_Block_Init(&block);
    BF_ErrorCode result = BF_GetBlock(file_descriptor, last_block, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    void *data = BF_Block_GetData(block);
    HP_block_info *hp_block_info = data + hp_info->max_records*sizeof(Record);
    int num_of_records = hp_block_info->num_of_records;

    if (last_block == 0 || num_of_records == max_records) {
        result = BF_AllocateBlock(file_descriptor, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        hp_info->last_block++;

        data = BF_Block_GetData(block);
        Record *rec = data;
        memcpy(rec, &record, sizeof(Record));

        HP_block_info new_hp_block_info;
        new_hp_block_info.num_of_records = 1;
        new_hp_block_info.next_block = -1;
        
        memcpy(data + max_records*sizeof(Record), &new_hp_block_info, sizeof(HP_block_info));
        
        BF_Block_SetDirty(block);

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        int prev_block = last_block;
        result = BF_GetBlock(file_descriptor, prev_block, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        data = BF_Block_GetData(block);
        HP_block_info *prev_hp_block_info = data + hp_info->max_records*sizeof(Record);
        prev_hp_block_info->next_block = prev_block + 1;

        BF_Block_SetDirty(block);

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        BF_Block_Destroy(&block);

        return prev_block + 1;
    }

    data = BF_Block_GetData(block);
    Record *rec = data;
    memcpy(rec + num_of_records*sizeof(Record), &record, sizeof(Record));

    hp_block_info->num_of_records++;

    BF_Block_SetDirty(block);
    
    result = BF_UnpinBlock(block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_Destroy(&block);

    return last_block;
}

int HP_GetAllEntries(HP_info* hp_info, int value) {
    int file_descriptor = hp_info->file_descriptor;

    int blocks_num;
    BF_ErrorCode result = BF_GetBlockCounter(file_descriptor, &blocks_num);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block *block;
    BF_Block_Init(&block);
    for (int block_id = 1; block_id < blocks_num; block_id++) {
        result = BF_GetBlock(file_descriptor, block_id, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        void *data = BF_Block_GetData(block);

        Record *rec = data;

        HP_block_info *hp_block_info = data + hp_info->max_records*sizeof(Record);
        int num_of_records = hp_block_info->num_of_records;
        for (int record_id = 0; record_id < num_of_records; record_id++) {
            if (rec[record_id].id == value)
                printRecord(rec[record_id]);
        }

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }
    }

    BF_Block_Destroy(&block);

    return blocks_num - 1;
}
