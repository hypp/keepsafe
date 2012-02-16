
CURRENT_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_PATH := $(CURRENT_PATH)/polarssl/library

LOCAL_C_INCLUDES := $(CURRENT_PATH)/polarssl/include

LOCAL_MODULE    := polarssl
LOCAL_SRC_FILES := aes.c sha1.c md_wrap.c md.c timing.c havege.c

include $(BUILD_STATIC_LIBRARY)

# second lib, which will depend on and include the first one
#
include $(CLEAR_VARS)

LOCAL_PATH := $(CURRENT_PATH)

LOCAL_C_INCLUDES := $(CURRENT_PATH)/polarssl/include

LOCAL_MODULE    := keepsafe
LOCAL_SRC_FILES := keepsafe.c pbkdf2.c

LOCAL_STATIC_LIBRARIES := polarssl


include $(BUILD_SHARED_LIBRARY)
