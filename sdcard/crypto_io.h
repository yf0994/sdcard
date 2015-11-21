#ifndef __CRYPTO_IO_H
#define __CRYPTO_IO_H
#define LOG_TAG "sdcard"
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <cutils/log.h>
#include <cutils/hashmap.h>

#define ERROR(x...) ALOGE(x)

int getsize(int fd);

int cryptoWrite(int fd, const char* data, int length, off_t offset, unsigned char* key);

int cryptoRead(int fd, __u8* data, int length, off_t offset, unsigned char* key);

int file_pread(int fd, char* data, ssize_t length, __u64 offset, unsigned char* key, Hashmap* map);

int file_pwrite(int fd, const char* data, ssize_t length, off_t offset, unsigned char* key);

#endif