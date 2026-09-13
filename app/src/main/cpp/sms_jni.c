#include <jni.h>
#include <stdint.h>

#include "sms_parser.h"

JNIEXPORT jstring JNICALL
Java_lab_purrview_SmsDecodeService_decodePdu(JNIEnv *env, jobject self,
                                             jbyteArray input, jboolean fixed) {
  (void)self;
  if (input == NULL) return (*env)->NewStringUTF(env, "REJECTED | no input");
  jsize size = (*env)->GetArrayLength(env, input);
  if (size > 128 * 1024) {
    return (*env)->NewStringUTF(env, "REJECTED | input exceeds 128 KiB");
  }
  jbyte *bytes = (*env)->GetByteArrayElements(env, input, NULL);
  if (bytes == NULL) return (*env)->NewStringUTF(env, "REJECTED | JNI access failed");
  char result[512];
  (void)parse_purrview_pdu((const unsigned char *)bytes, (size_t)size,
                           fixed == JNI_TRUE, result, sizeof(result));
  (*env)->ReleaseByteArrayElements(env, input, bytes, JNI_ABORT);
  return (*env)->NewStringUTF(env, result);
}
