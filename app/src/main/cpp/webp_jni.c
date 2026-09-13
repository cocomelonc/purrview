#include <jni.h>
#include <stdint.h>
#include <stdlib.h>

#include "webp_bridge.h"

JNIEXPORT jstring JNICALL
Java_lab_purrview_WebpDecodeService_decodeWebp(JNIEnv *env, jobject self,
                                               jbyteArray input) {
  (void)self;
  if (input == NULL) return (*env)->NewStringUTF(env, "REJECTED | no input");
  jsize size = (*env)->GetArrayLength(env, input);
  if (size > 256 * 1024) {
    return (*env)->NewStringUTF(env, "REJECTED | input exceeds 256 KiB");
  }
  jbyte *bytes = (*env)->GetByteArrayElements(env, input, NULL);
  if (bytes == NULL) return (*env)->NewStringUTF(env, "REJECTED | JNI access failed");
  char result[256];
  (void)decode_webp_vulnerable((const uint8_t *)bytes, (size_t)size,
                               result, sizeof(result));
  (*env)->ReleaseByteArrayElements(env, input, bytes, JNI_ABORT);
  return (*env)->NewStringUTF(env, result);
}
