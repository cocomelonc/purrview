#include <android/log.h>
#include <dlfcn.h>
#include <jni.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>

#include "parser.h"

#define ASLR_LOG_TAG "PurrView/ASLR"
#define ASLR_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, ASLR_LOG_TAG, __VA_ARGS__))

static void purrview_aslr_anchor(void) {}

JNIEXPORT jstring JNICALL
Java_lab_purrview_MainActivity_selfAslr(JNIEnv *env, jobject self) {
  (void)self;
  Dl_info info;
  if (dladdr((void *)purrview_aslr_anchor, &info) == 0 || info.dli_fbase == NULL) {
    return (*env)->NewStringUTF(env, "ASLR SELF | module lookup failed");
  }
  uintptr_t base = (uintptr_t)info.dli_fbase;
  uintptr_t symbol = (uintptr_t)(void *)purrview_aslr_anchor;
  uintptr_t slide = symbol - base;
  int page_aligned = (base & 0xfffu) == 0;
  char result[512];
  snprintf(result, sizeof(result),
           "ASLR SELF | EDUCATIONAL AND RESEARCH PURPOSES\n"
           "pid=%d module=%s\n"
           "base=0x%llx symbol=0x%llx slide=0x%llx page_aligned=%s",
           (int)getpid(), info.dli_fname != NULL ? info.dli_fname : "libpurrview.so",
           (unsigned long long)base, (unsigned long long)symbol,
           (unsigned long long)slide, page_aligned ? "yes" : "no");
  ASLR_LOGI("self module=%s pid=%d base=0x%llx symbol=0x%llx slide=0x%llx",
            info.dli_fname != NULL ? info.dli_fname : "libpurrview.so", (int)getpid(),
            (unsigned long long)base, (unsigned long long)symbol,
            (unsigned long long)slide);
  return (*env)->NewStringUTF(env, result);
}

JNIEXPORT jstring JNICALL
Java_lab_purrview_MainActivity_inspect(JNIEnv *env, jobject self,
                                       jbyteArray input, jboolean fixed) {
  (void)self;
  if (!input) return (*env)->NewStringUTF(env, "REJECTED | Missing input");
  jsize n = (*env)->GetArrayLength(env, input);
  if (n > 1048576) return (*env)->NewStringUTF(env, "REJECTED | File exceeds 1 MiB");
  jbyte *data = (*env)->GetByteArrayElements(env, input, 0);
  if (!data) return NULL;
  char result[1024];
  inspect_png((const uint8_t *)data, (size_t)n, fixed, result, sizeof(result));
  (*env)->ReleaseByteArrayElements(env, input, data, JNI_ABORT);
  return (*env)->NewStringUTF(env, result);
}
