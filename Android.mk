LOCAL_PATH := $(call my-dir)

include $(CLEAR_VARS)

LOCAL_MODULE := s8_poc

LOCAL_C_INCLUDES := \
	$(LOCAL_PATH)/libsepol/include \
	$(LOCAL_PATH)/poc/include

LOCAL_SRC_FILES := \
poc/main.c \
poc/bad_binder.c \
poc/kernel_rw.c \
poc/dac_bypass.c \
poc/kallsyms.c \
poc/selinux_bypass.c \
poc/knox_bypass.c

LOCAL_STATIC_LIBRARIES := libsepol

include $(BUILD_EXECUTABLE)

include $(CLEAR_VARS)

LOCAL_MODULE := test_elf

LOCAL_SRC_FILES := \
    test_elf/main.c

LOCAL_LDLIBS := -llog

include $(BUILD_EXECUTABLE)


$(call import-add-path, $(LOCAL_PATH))
$(call import-module, libsepol)