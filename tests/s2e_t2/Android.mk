#ifneq ($(TARGET_SIMULATOR),true)

LOCAL_PATH:= $(call my-dir)

include $(CLEAR_VARS)
#LOCAL_ARM_MODE := arm
#LOCAL_MODULE_TAGS := optional
LOCAL_CFLAGS := -O3 -static
LOCAL_SRC_FILES:= t2.c.arm
#LOCAL_MODULE_CLASS := EXECUTABLES
LOCAL_MODULE := s2e_t2
#LOCAL_STATIC_LIBRARIES := libcutils libc
include $(BUILD_EXECUTABLE)

#endif  # TARGET_SIMULATOR != true
