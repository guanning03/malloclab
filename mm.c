/*
 * mm-naive.c - The fastest, least memory-efficient malloc package.
 *
 * In this naive approach, a block is allocated by simply incrementing
 * the brk pointer.  A block is pure payload. There are no headers or
 * footers.  Blocks are never mergeHeapd or reused. Realloc is
 * implemented directly using mm_malloc and mm_free.
 *
 * NOTE TO STUDENTS: ReplaceHeap this header comment with your own header
 * comment that gives a high level description of your solution.
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "memlib.h"
#include "mm.h"

/*********************************************************
 * NOTE TO STUDENTS: Before you do anything else, please
 * provide your team information in the following struct.
 ********************************************************/
team_t team = {
  /* Team name */
  "曾冠宁",
  /* First member's full name */
  "曾冠宁",
  /* First member's email address */
  "zgn21@mails.tsinghua.edu.cn",
  /* Second member's full name (leave blank if none) */
  "",
  /* Second member's email address (leave blank if none) */
  ""
};

/* 16 bytes alignment */
#define ALIGNMENT 16

/* rounds up to the nearestSize multiple of ALIGNMENT */
#define ALIGN(size) (((size) + (ALIGNMENT - 1)) & ~(ALIGNMENT - 1))

#define SIZE_T_SIZE (ALIGN(sizeof(size_t)))

// 初始创建堆的大小
#define INIT_SIZE   512

// 每次扩展堆的大小
#define CHUNKSIZE   4096

// 链表的数量
#define LISTNUM     16

// 大块阈值
#define BIGSIZE     128

// 读写头部或脚部
#define PACK(size, alloc) ((size) | (alloc))
#define GET_SIZE(p)  (GET(p) & ~0x7)
#define GET_ALLOC(p) (GET(p) & 0x1)
#define HDRP(p) ((char *)(p) - 4)
#define FTRP(p) ((char *)(p) + GET_SIZE(HDRP(p)) - 8)

// 得到块的大小
#define GET_BLK_SIZE(p) (GET_SIZE(HDRP(p)))

// 读写指针p所指向的内存
#define GET(p)            (*(unsigned int *)(p))
#define PUT(p, val)       (*(unsigned int *)(p) = (val))
#define SET_PTR(p, addr) (*(size_t *)(p) = (size_t)(addr))

// 得到内存意义上的前后块地址
#define NEXT_BLKP(p) ((char *)(p) + GET_SIZE((char *)(p) - 4))
#define PREV_BLKP(p) ((char *)(p) - GET_SIZE((char *)(p) - 8))

// 得到链表意义上的前后块
#define PRED_PTR(p) ((char *)(p))
#define SUCC_PTR(p) ((char *)(p) + 8)
#define PRED(p) (*(char **)(p))
#define SUCC(p) (*(char **)(SUCC_PTR(p)))

// 比大小
#define MAX(x, y) ((x) > (y) ? (x) : (y))

// 分离空闲表
void *freeLists[LISTNUM];

// 扩展堆函数
void * extendHeap(size_t size);

// 合并块函数
void * mergeHeap(void *blockPtr);

// 放置块函数
void * placeHeap(void *blockPtr, size_t size);

// 链表操作函数
void insertNode(void *blockPtr, size_t size);
void deleteNode(void *blockPtr);

void * extendHeap(size_t size) {
    void *ptr;
    size = ALIGN(size);
    // 扩展堆
    if ((ptr = mem_sbrk(size)) == (void *)-1) return NULL;
    // 初始化新的空闲块
    PUT(HDRP(ptr), PACK(size, 0));
    PUT(FTRP(ptr), PACK(size, 0));
    PUT(HDRP(NEXT_BLKP(ptr)), PACK(0, 1));
    // 将新的空闲块插入链表
    insertNode(ptr, size);
    // 合并空闲块，返回合并后的块
    return mergeHeap(ptr);
}

char findListIdx (size_t size) {
    int l = 0;
    for (;l < LISTNUM - 1; l++) {
        if (size <= 1) break;
        size >>= 1;
    }
    return l;
}

// 向链表中插入节点
void insertNode(void *blockPtr, size_t size) {
    // 扫描链表，找到合适的链条
    int l = findListIdx(size);
    void *currentBlock = NULL;
    void *previousBlock = NULL;
    currentBlock = freeLists[l];
    // 找到第一个比当前块大的块
    while ((currentBlock != NULL) && (size > GET_BLK_SIZE(currentBlock))) {
        previousBlock = currentBlock;
        currentBlock = PRED(currentBlock);
    }
    // 插入节点，分四种情况
    if (currentBlock == NULL && previousBlock == NULL) {
        // 1. 链表为空
        freeLists[l] = blockPtr;
        SET_PTR(PRED_PTR(blockPtr), NULL);
        SET_PTR(SUCC_PTR(blockPtr), NULL);
    } else if (currentBlock != NULL && previousBlock == NULL) {
        // 2. 插入到链表头部
        freeLists[l] = blockPtr;
        SET_PTR(PRED_PTR(blockPtr), currentBlock);
        SET_PTR(SUCC_PTR(currentBlock), blockPtr);
        SET_PTR(SUCC_PTR(blockPtr), NULL);
    } else if (currentBlock == NULL && previousBlock != NULL) {
        // 3. 插入到链表尾部
        SET_PTR(PRED_PTR(blockPtr), NULL);
        SET_PTR(SUCC_PTR(blockPtr), previousBlock);
        SET_PTR(PRED_PTR(previousBlock), blockPtr);
    } else if (currentBlock != NULL && previousBlock != NULL) {
        // 4. 插入到链表中间
        SET_PTR(PRED_PTR(blockPtr), currentBlock);
        SET_PTR(SUCC_PTR(currentBlock), blockPtr);
        SET_PTR(SUCC_PTR(blockPtr), previousBlock);
        SET_PTR(PRED_PTR(previousBlock), blockPtr);
    }
}

void deleteNode(void *blockPtr)
{
    int l = findListIdx(GET_BLK_SIZE(blockPtr));
    size_t size = GET_BLK_SIZE(blockPtr);
    // 同样也是四种情况
    if (PRED(blockPtr) == NULL && SUCC(blockPtr) == NULL) {
        // 1. 链表只有一个节点
        freeLists[l] = NULL;
    } else if (PRED(blockPtr) != NULL && SUCC(blockPtr) == NULL) {
        // 2. 删除的是链表尾部
        freeLists[l] = PRED(blockPtr);
        SET_PTR(SUCC_PTR(PRED(blockPtr)), NULL);
    } else if (PRED(blockPtr) == NULL && SUCC(blockPtr) != NULL) {
        // 3. 删除的是链表头部
        SET_PTR(PRED_PTR(SUCC(blockPtr)), NULL);
    } else {
        // 4. 删除的是链表中间
        SET_PTR(SUCC_PTR(PRED(blockPtr)), SUCC(blockPtr));
        SET_PTR(PRED_PTR(SUCC(blockPtr)), PRED(blockPtr));
    }
}

void * mergeHeap(void *blockPtr) {
    unsigned char lastBlockMerge = GET_ALLOC(HDRP(PREV_BLKP(blockPtr)));
    unsigned char nextBlockMerge = GET_ALLOC(HDRP(NEXT_BLKP(blockPtr)));
    size_t size = GET_BLK_SIZE(blockPtr);
    // 合并空闲块，分四种情况
    if (lastBlockMerge && nextBlockMerge) {
        // 1. 前后都不可合并
        return blockPtr;
    } else if (lastBlockMerge && !nextBlockMerge) {
        // 2. 后可合并
        deleteNode(blockPtr);
        deleteNode(NEXT_BLKP(blockPtr));
        size += GET_BLK_SIZE(NEXT_BLKP(blockPtr));
        PUT(HDRP(blockPtr), PACK(size, 0));
        PUT(FTRP(blockPtr), PACK(size, 0));
    } else if (!lastBlockMerge && nextBlockMerge) {
        // 3. 前可合并
        deleteNode(blockPtr);
        deleteNode(PREV_BLKP(blockPtr));
        size += GET_BLK_SIZE(PREV_BLKP(blockPtr));
        PUT(FTRP(blockPtr), PACK(size, 0));
        PUT(HDRP(PREV_BLKP(blockPtr)), PACK(size, 0));
        blockPtr = PREV_BLKP(blockPtr);
    } else {
        // 4. 前后都可合并
        deleteNode(blockPtr);
        deleteNode(PREV_BLKP(blockPtr));
        deleteNode(NEXT_BLKP(blockPtr));
        size += GET_BLK_SIZE(PREV_BLKP(blockPtr)) + GET_BLK_SIZE(NEXT_BLKP(blockPtr));
        PUT(HDRP(PREV_BLKP(blockPtr)), PACK(size, 0));
        PUT(FTRP(NEXT_BLKP(blockPtr)), PACK(size, 0));
        blockPtr = PREV_BLKP(blockPtr);
    }
    insertNode(blockPtr, size);
    return blockPtr;
}

void * placeHeap(void *blockPtr, size_t size) {
    size_t blockPtr_size = GET_BLK_SIZE(blockPtr);
    size_t restSize = blockPtr_size - size;
    deleteNode(blockPtr);
    // 放置块，分三种情况
    if (restSize < 32) {
        // 1. 剩余块太小，不分割
        PUT(HDRP(blockPtr), PACK(blockPtr_size, 1));
        PUT(FTRP(blockPtr), PACK(blockPtr_size, 1));
        return blockPtr;
    } else if (size >= BIGSIZE) {
        // 2. 如果这个块看起来比较大，就放到后面
        PUT(HDRP(blockPtr), PACK(restSize, 0));
        PUT(FTRP(blockPtr), PACK(restSize, 0));
        PUT(HDRP(NEXT_BLKP(blockPtr)), PACK(size, 1));
        PUT(FTRP(NEXT_BLKP(blockPtr)), PACK(size, 1));
        insertNode(blockPtr, restSize);
        return NEXT_BLKP(blockPtr);
    } else {
        // 3. 如果这个块看起来比较小，就放到前面
        PUT(HDRP(blockPtr), PACK(size, 1));
        PUT(FTRP(blockPtr), PACK(size, 1));
        PUT(HDRP(NEXT_BLKP(blockPtr)), PACK(restSize, 0));
        PUT(FTRP(NEXT_BLKP(blockPtr)), PACK(restSize, 0));
        insertNode(NEXT_BLKP(blockPtr), restSize);
         return blockPtr;
    }
}

int mm_init(void) {
    // 初始化空闲链表
    for (int l = 0; l < LISTNUM; l++) freeLists[l] = NULL;
    char * heap = mem_sbrk(16);
    // 初始化堆
    if ((size_t) heap == (size_t)-1) return -1;
    // 初始化堆的头部，作为哨兵
    PUT(heap, 0);
    PUT(heap + 4 , PACK(8, 1));
    PUT(heap + 8 , PACK(8, 1));
    PUT(heap + 12, PACK(0, 1));
    // 扩展堆，初始一段大小为INIT_SIZE的空闲块
    if (extendHeap(INIT_SIZE) == NULL) return -1;
    return 0;
}   

void adjustSize (size_t *size) {
    if (*size <= 16) *size = 16;
    *size = ALIGN(*size + 8);
}

void * mm_malloc(size_t size) {
    adjustSize(&size);
    void * blockPtr = NULL;
    // 先确定所在链条，然后顺序遍历找到恰好能放下的块
    for (int l = findListIdx(size); l < LISTNUM; l++) {
        if (freeLists[l] != NULL) {
            blockPtr = freeLists[l];
            while (blockPtr != NULL && size > GET_BLK_SIZE(blockPtr)) blockPtr = PRED(blockPtr);
            if (blockPtr != NULL) break;
        }
    }
    // 如果没有找到，就扩展堆
    if (blockPtr == NULL) blockPtr = extendHeap(MAX(size, CHUNKSIZE));
    // 放置块，将剩余块插入链表
    return blockPtr ? placeHeap(blockPtr, size): NULL;
}

void mm_free(void *blockPtr) {
    size_t size = GET_BLK_SIZE(blockPtr);
    // 释放块，插入链表，合并块
    PUT(HDRP(blockPtr), PACK(size, 0));
    PUT(FTRP(blockPtr), PACK(size, 0));
    insertNode(blockPtr, size);
    mergeHeap(blockPtr);
}

void* replaceBlockWithNew(size_t size, void* blockPtr) {
    void* newBlock = mm_malloc(size);
    memcpy(newBlock, blockPtr, GET_BLK_SIZE(blockPtr));
    mm_free(blockPtr);
    return newBlock;
}

void *mm_realloc(void *blockPtr, size_t size) {
    adjustSize(&size);
    void *newBlock = blockPtr;
    int restSize = GET_BLK_SIZE(blockPtr) - size;
    // 1. 如果新的大小小于原来的大小，不需要分配
    if (restSize >= 0)  return blockPtr;
    // 2. 如果新的大小大于原来的大小
    else if (!GET_ALLOC(HDRP(NEXT_BLKP(blockPtr)))) {
        restSize = GET_BLK_SIZE(blockPtr) + GET_BLK_SIZE(NEXT_BLKP(blockPtr)) - size;
        // 2. 但是后面的块是空闲块，且合并后的大小大于等于所需大小，就合并
        if (restSize >= 0) {
            deleteNode(NEXT_BLKP(blockPtr));
            PUT(HDRP(blockPtr), PACK(size + restSize, 1));
            PUT(FTRP(blockPtr), PACK(size + restSize, 1));
        } else {
            // 3. 否则，重新分配
            newBlock = replaceBlockWithNew(size, blockPtr);
        }
    } else {
        // 3. 重新分配
        newBlock = replaceBlockWithNew(size, blockPtr);
    }
    return newBlock;
}

