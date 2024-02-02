#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include "../include/bf.h"
#include "../include/ht_table.h"
#include "../include/record.h"

#define CALL_OR_DIE(call)       \
{                               \
    BF_ErrorCode code = call;   \
    if (code != BF_OK) {        \
    	BF_PrintError(code);    \
    	exit(code);             \
    }                           \
}                               \


int HT_CreateFile(char *fileName, int buckets) {
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

    HT_info ht_info;
    ht_info.file_type = HT_FILE;
    ht_info.file_descriptor = file_descriptor;
    ht_info.block_id = 0;
    ht_info.num_of_buckets = buckets;
    ht_info.hash_table = malloc(buckets*sizeof(int));
    for (int i = 0; i < buckets; i++)
        ht_info.hash_table[i] = -1;
    ht_info.max_records = (BF_BLOCK_SIZE - sizeof(HT_block_info)) / sizeof(Record);

    memcpy(data, &ht_info, sizeof(HT_info));

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

HT_info* HT_OpenFile(char *fileName) {
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
    HT_info* ht_ifo = malloc(sizeof(HT_info));
    ht_ifo = data;
    if (ht_ifo->file_type != HT_FILE)
        return NULL;

    BF_Block_Destroy(&block);

    return ht_ifo;
}


int HT_CloseFile(HT_info* ht_info) {
    int file_descriptor = ht_info->file_descriptor;

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

    // free(ht_info->hash_table);

    // free(ht_info);

    return 0;
}

int HT_InsertEntry (HT_info *ht_info, Record record) {
    int file_descriptor = ht_info->file_descriptor;

    int max_records = ht_info->max_records;

    int bucket = record.id % ht_info->num_of_buckets;
    int block_id = ht_info->hash_table[bucket];

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

        void *data = BF_Block_GetData(block);
        Record *rec = data;
        memcpy(rec, &record, sizeof(Record));

        ht_info->hash_table[bucket] = blocks_num - 1;

        HT_block_info new_ht_back_info;
        new_ht_back_info.num_of_records = 1;
        new_ht_back_info.overflow_block_id = -1;

        memcpy(data + max_records*sizeof(Record), &new_ht_back_info, sizeof(HT_block_info));

        BF_Block_SetDirty(block);

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        BF_Block_Destroy(&block);

        return blocks_num;
    }
    
    BF_ErrorCode result = BF_GetBlock(file_descriptor, block_id, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    void *data = BF_Block_GetData(block);
    HT_block_info *ht_block_info = data + ht_info->max_records*sizeof(Record);
    int num_of_records = ht_block_info->num_of_records;
    
    if (num_of_records == max_records) {
        result = BF_AllocateBlock(file_descriptor, block);
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
        Record *rec = data;
        memcpy(rec, &record, sizeof(Record));

        HT_block_info new_ht_block_info;
        new_ht_block_info.num_of_records = 1;
        new_ht_block_info.overflow_block_id = block_id;

        memcpy(data + max_records*sizeof(Record), &new_ht_block_info, sizeof(HT_block_info));

        ht_info->hash_table[bucket] = blocks_num - 1;

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
        HT_block_info *prev_ht_block_info = data + ht_info->max_records*sizeof(Record);
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

    memcpy(data + num_of_records*sizeof(Record), &record, sizeof(Record));
    ht_block_info->num_of_records++;

    BF_Block_SetDirty(block);

    result = BF_UnpinBlock(block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block_Destroy(&block);

    return block_id;
}

int HT_GetAllEntries (HT_info* ht_info, int *id) {
    int file_descriptor = ht_info->file_descriptor;
    
    int bucket = *id % ht_info->num_of_buckets;
    int block_id = ht_info->hash_table[bucket];

    int block_count = 0;

    BF_Block *block;
    BF_Block_Init(&block);

    while (block_id != -1) {
        BF_ErrorCode result = BF_GetBlock(file_descriptor, block_id, block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        void *data = BF_Block_GetData(block);
        
        Record *rec = data;

        HT_block_info *ht_block_info = data + ht_info->max_records*sizeof(Record);
        int num_of_records = ht_block_info->num_of_records;
        for (int record_id = 0; record_id < num_of_records; record_id++) {
            if (rec[record_id].id == *id)
                printRecord(rec[record_id]);
        }

        result = BF_UnpinBlock(block);
        if (result != BF_OK) {
            BF_PrintError(result);
            return -1;
        }

        block_id = ht_block_info->overflow_block_id;

        block_count++;
    }

    BF_Block_Destroy(&block);

    return block_count;
}

int HashStatistics(char *fileName) {
    int file_descriptor;
    BF_ErrorCode result = BF_OpenFile(fileName, &file_descriptor);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    BF_Block *block;
    BF_Block_Init(&block);
    result = BF_GetBlock(file_descriptor, 0, block);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }
    
    void *data = BF_Block_GetData(block);

    HT_info *ht_info = data;

    int blocks_num;
    result = BF_GetBlockCounter(file_descriptor, &blocks_num);
    if (result != BF_OK) {
        BF_PrintError(result);
        return -1;
    }

    printf("Nuber of blocks in HT_FILE: %d\n", blocks_num);
    
    double avg_blocks_in_bucket = (double)blocks_num / ht_info->num_of_buckets;
    printf("Average number of blocks in each bucket: %f\n", avg_blocks_in_bucket);

    int records_sum = 0;
    int min_records, max_records = 0;
    double avg_records = 0;

    int buckets_with_overflow_blocks = 0;

    for (int bucket = 0; bucket < ht_info->num_of_buckets; bucket++) {
        int block_id = ht_info->hash_table[bucket];

        if (block_id == -1)
            continue;

        int overflow_blocks = -1;

        int bucket_records = 0;
        while (block_id != -1) {
            result = BF_GetBlock(file_descriptor, block_id, block);
            if (result != BF_OK) {
                BF_PrintError(result);
                return -1;
            }

            void *data = BF_Block_GetData(block);

            HT_block_info *ht_block_info = data + ht_info->max_records*sizeof(Record);

            bucket_records += ht_block_info->num_of_records;

            overflow_blocks++;

            result = BF_UnpinBlock(block);
            if (result != BF_OK) {
                BF_PrintError(result);
                return -1;
            }

            block_id = ht_block_info->overflow_block_id;            
        }

        if (bucket_records < min_records || bucket == 0)
            min_records = bucket_records;

        if (bucket_records > max_records)
            max_records = bucket_records;

        records_sum += bucket_records;

        if (overflow_blocks > 0) {
            buckets_with_overflow_blocks++;
            printf("Overflow blocks of bucket %d: %d\n", bucket, overflow_blocks - 1);
        }
    }

    avg_records = (double)records_sum / ht_info->num_of_buckets;
    printf("Min: %d, Avg: %f, Max: %d\n", min_records, avg_records, max_records);

    printf("Buckets with overflow blocks: %d\n", buckets_with_overflow_blocks);

    BF_Block_Destroy(&block);

    return 0;
}