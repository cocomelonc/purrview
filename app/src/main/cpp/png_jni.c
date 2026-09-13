#include <jni.h>
#include <stdint.h>

#include "parser.h"

JNIEXPORT jstring JNICALL
Java_lab_purrview_PngDecodeService_decodePng(JNIEnv *env, jobject self,
                                             jbyteArray input, jboolean fixed) {
  (void) self;
  if (input == NULL) return (*env)->NewStringUTF(env, "REJECTED | no input");

  jsize size = (*env)->GetArrayLength(env, input);
  if (size > 1024 * 1024) {
    return (*env)->NewStringUTF(env, "REJECTED | input exceeds 1 MiB");
  }

  jbyte *bytes = (*env)->GetByteArrayElements(env, input, NULL);
  if (bytes == NULL) return (*env)->NewStringUTF(env, "REJECTED | JNI access failed");

  char result[1024];
  (void) inspect_png((const uint8_t *) bytes, (size_t) size,
                     fixed == JNI_TRUE, result, sizeof(result));
  (*env)->ReleaseByteArrayElements(env, input, bytes, JNI_ABORT);
  return (*env)->NewStringUTF(env, result);
}
