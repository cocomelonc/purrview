#include <jni.h>

#include "jpeg_bridge.h"

JNIEXPORT jstring JNICALL
Java_lab_purrview_JpegDecodeService_decodePpmPath(JNIEnv *env, jobject self,
                                                  jstring path) {
  (void)self;
  if (path == NULL) return (*env)->NewStringUTF(env, "REJECTED | no PPM path");
  const char *utf_path = (*env)->GetStringUTFChars(env, path, NULL);
  if (utf_path == NULL) {
    return (*env)->NewStringUTF(env, "REJECTED | JNI path access failed");
  }
  char result[256];
  (void)decode_ppm_file(utf_path, result, sizeof(result));
  (*env)->ReleaseStringUTFChars(env, path, utf_path);
  return (*env)->NewStringUTF(env, result);
}
