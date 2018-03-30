LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE    := elf_loader
LOCAL_SRC_FILES := elf_loader.c
LOCAL_LDLIBS	:= -llog -lz
include $(BUILD_SHARED_LIBRARY)