LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_SRC_FILES := sdcard.c crypto_io.c cipher_helper.c
LOCAL_MODULE := sdcard
LOCAL_CFLAGS := -Wall -Wno-unused-parameter
LOCAL_C_INCLUDES += external/openssl/include

LOCAL_SHARED_LIBRARIES := libc libcutils libcrypto

include $(BUILD_EXECUTABLE)
