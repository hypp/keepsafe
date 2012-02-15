
CURRENT_PATH := $(call my-dir)
LOCAL_PATH := $(CURRENT_PATH)/polarssl-1.1.1/library

include $(CLEAR_VARS)

LOCAL_C_INCLUDES := $(CURRENT_PATH)/polarssl-1.1.1/include

LOCAL_MODULE    := polarssl
LOCAL_SRC_FILES := aes.c sha1.c md_wrap.c md.c timing.c havege.c

include $(BUILD_STATIC_LIBRARY)

# second lib, which will depend on and include the first one
#
include $(CLEAR_VARS)

LOCAL_PATH := $(CURRENT_PATH)

LOCAL_MODULE    := keepsafe
LOCAL_SRC_FILES := keepsafe.c

LOCAL_STATIC_LIBRARIES := polarssl

include $(BUILD_SHARED_LIBRARY)
