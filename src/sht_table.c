#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "bf.h"
#include "sht_table.h"
#include "ht_table.h"
#include "record.h"

#define CALL_OR_DIE(call)		\
{								\
	BF_ErrorCode code = call;	\
    if (code != BF_OK) {		\
    	BF_PrintError(code);	\
    	exit(code);				\
	}							\
}								\


int SHT_CreateSecondaryIndex(char *sfileName, int buckets, char *fileName) {
    BF_ErrorCode result = BF_CreateFile(sfileName);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

	int sht_file_descriptor;
    result = BF_OpenFile(sfileName, &sht_file_descriptor);
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

    SHT_info sht_info;
    sht_info.file_type = SHT_FILE;
    sht_info.file_descriptor = file_descriptor;
    sht_info.block_id = 0;
    sht_info.num_of_buckets = buckets;
    sht_info.hash_table = malloc(buckets*sizeof(int));
    for (int i = 0; i < buckets; i++)
        sht_info.hash_table[i] = -1;
    sht_info.max_pairs = (BF_BLOCK_SIZE - sizeof(HT_block_info)) / sizeof(SHT_pair);

    memcpy(data, &sht_info, sizeof(SHT_info));

    BF_Block_SetDirty(block);

    result = BF_UnpinBlock(block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_Destroy(&block);

    result = BF_CloseFile(sht_file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    return 0;
}

SHT_info* SHT_OpenSecondaryIndex(char *indexName) {
	int sht_file_descriptor;

    BF_ErrorCode result = BF_OpenFile(indexName, &sht_file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return NULL;
    }

    BF_Block *block;
    BF_Block_Init(&block);
    result = BF_GetBlock(sht_file_descriptor, 0, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return NULL;
    }
    
    void *data = BF_Block_GetData(block);
    SHT_info *sht_ifo = malloc(sizeof(SHT_info));
    sht_ifo = data;
    if (sht_ifo->file_type != SHT_FILE)
        return NULL;

    BF_Block_Destroy(&block);

    return sht_ifo;
}

int SHT_CloseSecondaryIndex(SHT_info* sht_info) {
    int sht_file_descriptor = sht_info->file_descriptor;

    BF_Block *block;
  	BF_Block_Init(&block);
    BF_ErrorCode result = BF_GetBlock(sht_file_descriptor, 0, block);
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

    result = BF_CloseFile(sht_file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    // Double free
    // free(sht_info->hash_table);

    // free(sht_info);

    return 0;
}

int SHT_SecondaryInsertEntry(SHT_info* sht_info, Record record, int block_id) {
    int file_descriptor = sht_info->file_descriptor;

    int max_pairs = sht_info->max_pairs;

    SHT_pair sht_pair;
    sht_pair.block_id = block_id;

    strcpy(sht_pair.name, record.name);

    int hash_value = 0;
    for (int c = 0; c != '\0'; c++)
        hash_value += (int)record.name[c];

    int bucket = hash_value % sht_info->num_of_buckets;

    BF_Block *block;
    BF_Block_Init(&block);

    if (block_id == -1) {
        BF_ErrorCode result = BF_AllocateBlock(file_descriptor, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        int blocks_num;
        result = BF_GetBlockCounter(file_descriptor, &blocks_num);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        sht_info->hash_table[bucket] = blocks_num - 1;

        void *data = BF_Block_GetData(block);
        SHT_pair *sht_pairs = data;
        memcpy(sht_pairs, &sht_pair, sizeof(SHT_pair));

        sht_info->hash_table[bucket] = blocks_num;

        SHT_block_info new_sht_back_info;
        new_sht_back_info.block_id = blocks_num - 1;
        new_sht_back_info.num_of_pairs = 1;
        new_sht_back_info.overflow_block_id = -1;

        memcpy(data + max_pairs*sizeof(SHT_pair), &new_sht_back_info, sizeof(SHT_block_info));

        BF_Block_SetDirty(block);

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        BF_Block_Destroy(&block);

        return blocks_num - 1;
    }
    
    BF_ErrorCode result = BF_GetBlock(file_descriptor, block_id, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    void *data = BF_Block_GetData(block);
    SHT_block_info *sht_block_info = data + sht_info->max_pairs*sizeof(Record);
    int num_of_pairs = sht_block_info->num_of_pairs;
    
    if (num_of_pairs == max_pairs) {
        BF_ErrorCode result = BF_AllocateBlock(file_descriptor, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        int blocks_num;
        result = BF_GetBlockCounter(file_descriptor, &blocks_num);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        void *data = BF_Block_GetData(block);
        SHT_pair *sht_pairs = data;
        memcpy(sht_pairs, &sht_pair, sizeof(SHT_pair));

        SHT_block_info new_sht_block_info;
        new_sht_block_info.block_id = blocks_num - 1;
        new_sht_block_info.num_of_pairs = 1;
        new_sht_block_info.overflow_block_id = block_id;

        memcpy(data + max_pairs*sizeof(SHT_pair), &new_sht_block_info, sizeof(SHT_block_info));

        BF_Block_SetDirty(block);

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        result = BF_GetBlock(file_descriptor, block_id, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        data = BF_Block_GetData(block);
        HT_block_info *prev_ht_block_info = data + sht_info->max_pairs*sizeof(Record);
        prev_ht_block_info->overflow_block_id = -1;

        BF_Block_SetDirty(block);

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        BF_Block_Destroy(&block);

        return blocks_num - 1;
    }

    memcpy(data + num_of_pairs*sizeof(SHT_pair), &sht_pair, sizeof(SHT_pair));
    sht_block_info->num_of_pairs++;

    BF_Block_SetDirty(block);

    result = BF_UnpinBlock(block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_Destroy(&block);

    return block_id;
}

int SHT_SecondaryGetAllEntries(HT_info* ht_info, SHT_info* sht_info, char* name) {
    int sht_file_descriptor = sht_info->file_descriptor;
    int file_descriptor = ht_info->file_descriptor;

    int hash_value = 0;
    for (int c = 0; c != '\0'; c++)
        hash_value += (int)name[c];

    int bucket = hash_value % ht_info->num_of_buckets;
    int block_id = ht_info->hash_table[bucket];

    int block_count = 0;

    if (block_id == 0)
        return 0;

    BF_Block *block;
    BF_Block_Init(&block);

    while (block_id != -1) {
        BF_ErrorCode result = BF_GetBlock(sht_file_descriptor, block_id, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        void *data = BF_Block_GetData(block);
        
        SHT_pair *sht_pairs = data;

        SHT_block_info *sht_block_info = data + sht_info->max_pairs*sizeof(SHT_pair);
        int num_of_pairs = sht_block_info->num_of_pairs;
        for (int pair_id = 0; pair_id < num_of_pairs; pair_id++) {
            if (strcmp(sht_pairs[pair_id].name, name) == 0) {

                data = BF_Block_GetData(block);

                Record *rec = data;

                HT_block_info *ht_block_info = data + ht_info->max_records*sizeof(Record);
                int num_of_records = ht_block_info->num_of_records;
                for (int record_id = 0; record_id < num_of_records; record_id++) {
                    if (strcmp(sht_pairs[pair_id].name, name) == 0) {
                        printRecord(rec[pair_id]);
                    }
                }
            }
        }

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        block_id = sht_block_info->overflow_block_id;

        block_count++;
    }

    BF_Block_Destroy(&block);

    return block_count;
}
