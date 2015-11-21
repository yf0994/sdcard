#include "crypto_io.h"
//#include "cipher_helper.h"

#define BLOCK_SIZE 16
#define BLOCK_DATA_SIZE 17

//int file_open(const char* filepath){
//    int fd = open(filepath, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
//    return fd == -1 ? -1 : fd;
//}

ssize_t getsize(int fd){
    struct stat st;
    if(fstat(fd, &st) == -1){
        return 0;
    }
    char path[1024];
    char result[1024];

    sprintf(path,"/proc/self/fd/%d", fd);
    memset(result,0,sizeof(result));
    readlink(path, result,sizeof(result)-1);

        /* Print the result. */
    printf("%s\n", result);
    return st.st_size;
}

ssize_t file_pread(int fd, char* data, ssize_t length, __u64 offset, unsigned char* key, Hashmap* name_with_offset){
    char s[256], name[256];
    snprintf(s, 255, "/proc/%d/fd/%d", getpid(), fd);
    memset(name, 0, sizeof(name));
    readlink(s, name, 255);
    int filesize = getsize(fd);
    if(offset >= filesize){
        hashmapRemove(name_with_offset, (void*)(uintptr_t)name);
        return 0;
    }
    off_t dataBlockNum = length / BLOCK_SIZE;
    off_t dataPartialOffset = length % BLOCK_SIZE;
    if(dataPartialOffset != 0){
        dataBlockNum += 1;
    }
    int i;
    if(hashmapContainsKey(name_with_offset, (void*)(uintptr_t)name)){
        void* value = hashmapGet(name_with_offset, (void*)(uintptr_t)name);
        offset = (off_t)(uintptr_t)value;
    }
    unsigned char buffer[BLOCK_SIZE];
    unsigned char plaintext[BLOCK_SIZE];
    int ret = 0;
    int temp = offset;
    uint8_t size = 0;
    for(i = 0; i < dataBlockNum; i++){
        if((temp + (i + 1) * BLOCK_SIZE) <= filesize){
            if(offset < filesize){
                pread(fd, &size, sizeof(uint8_t), offset);
                pread(fd, buffer, BLOCK_SIZE, offset + 1);
                offset += BLOCK_DATA_SIZE;
                decrypts(buffer, plaintext);
                memcpy(data + ret, plaintext, size);
                ret += size;
                memset(buffer, 0, BLOCK_SIZE);
                memset(plaintext, 0, BLOCK_SIZE);
            }
        }
    }
    hashmapPut(name_with_offset, (void*)(uintptr_t)name, (void*)(uintptr_t)offset);
    return ret;
}

ssize_t file_pwrite(int fd, const char* data, ssize_t length, off_t offset, unsigned char* key){
    int i;
    off_t blockNum = 0;
    off_t remainder = 0;
    unsigned char buffer[BLOCK_SIZE];
    unsigned char ciphertext[BLOCK_SIZE];
    int ret = 0;
    int filesize = getsize(fd);
    if(offset > filesize){
        blockNum = offset / BLOCK_SIZE;
        remainder = offset % BLOCK_SIZE;
        if(remainder != 0){
            blockNum += 1;
        }
        offset = blockNum * BLOCK_SIZE;
    } else {
        offset = filesize;
    }

    off_t dataBlockNum = length / BLOCK_SIZE;
    off_t dataRemainder = length % BLOCK_SIZE;
    if(dataRemainder != 0){
        dataBlockNum += 1;
    }
    char tempBuffer[dataBlockNum * BLOCK_SIZE];
    int size = length;
    memset(buffer, 0, BLOCK_SIZE);
    memset(tempBuffer, 0, dataBlockNum * BLOCK_SIZE);
    memcpy(tempBuffer, data, length);
    uint8_t flag = BLOCK_SIZE;
    for(i = 0; i < dataBlockNum; i++){
        memcpy(buffer, tempBuffer + ret, BLOCK_SIZE);
        encrypts(buffer, ciphertext);
        if(size > BLOCK_SIZE){
            pwrite(fd, &flag, sizeof(uint8_t), offset);
            size -= BLOCK_SIZE;
        } else {
            pwrite(fd, &size, sizeof(uint8_t), offset);
        }
        pwrite(fd, ciphertext, BLOCK_SIZE, offset + 1);
        offset += BLOCK_DATA_SIZE;
        ret += BLOCK_DATA_SIZE;
        memset(buffer, 0, BLOCK_SIZE);
        memset(ciphertext, 0, BLOCK_SIZE);
    }
    return ret;
}

//void file_close(int fd, Hashmap* map){
//    close(fd);
//    if(hashmapContainsKey(map, (void*)(uintptr_t)fd)){
//        hashmapRemove(map, (void*)(uintptr_t)fd);
//    }
//}