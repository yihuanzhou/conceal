LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE    := conceal
LOCAL_CFLAGS    := -fvisibility=hidden -Os
LOCAL_SRC_FILES := cbc.c cbc_util.c gcm.c gcm_util.c hmac.c hmac_util.c init.c util.c
LOCAL_LDLIBS    := -llog

LOCAL_SHARED_LIBRARIES += crypto
include $(BUILD_SHARED_LIBRARY)

$(call import-module,openssl)
