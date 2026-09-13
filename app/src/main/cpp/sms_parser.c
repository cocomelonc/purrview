#include "sms_parser.h"

#include <android/log.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define SMS_LOG_TAG "PurrView/SMS"
#define SMS_LOGI(...) ((void)__android_log_print(ANDROID_LOG_INFO, SMS_LOG_TAG, __VA_ARGS__))
#define SMS_LOGE(...) ((void)__android_log_print(ANDROID_LOG_ERROR, SMS_LOG_TAG, __VA_ARGS__))

static int reject(char *out, size_t capacity, const char *reason) {
  snprintf(out, capacity, "REJECTED | %s", reason);
  return -1;
}

int parse_purrview_pdu(const unsigned char *data, size_t size, int fixed,
                       char *out, size_t capacity) {
  if (data == NULL || out == NULL || capacity == 0 || size < 6 ||
      memcmp(data, "PMS1", 4) != 0) {
    return reject(out, capacity, "invalid PurrView PDU envelope");
  }

  const size_t declared = ((size_t)data[4] << 8) | data[5];
  const size_t available = size - 6;
  const unsigned char *payload = data + 6;
  SMS_LOGI("PDU header | version=1 declared=%zu available=%zu mode=%s",
           declared, available, fixed ? "fixed" : "PoC");

  if (fixed) {
    if (declared > available || declared > 4096) {
      return reject(out, capacity, "PDU length exceeds input bounds");
    }
    unsigned char *message = (unsigned char *)malloc(declared + 1);
    if (message == NULL) return reject(out, capacity, "message allocation failed");
    memcpy(message, payload, declared);
    message[declared] = 0;
    SMS_LOGI("FIXED COPY | allocation=%zu copy=%zu", declared + 1, declared);
    snprintf(out, capacity, "FIXED SAFE | PurrView PDU | bytes=%zu", declared);
    free(message);
    return 0;
  }

  if (declared > available || declared > 4096) {
    return reject(out, capacity, "PDU length exceeds input bounds");
  }

  /* Deliberate PurrView-only bug: the 16-bit length is narrowed to 8 bits
     before allocation, while the full declared length is copied below. */
  const size_t allocation = (unsigned char)declared + 1u;
  unsigned char *message = (unsigned char *)malloc(allocation);
  if (message == NULL) return reject(out, capacity, "message allocation failed");
  SMS_LOGE("OOB WRITE | PurrView PDU parser | allocation=%zu copy=%zu source=%zu",
           allocation, declared, available);
  SMS_LOGE("memcpy(dst=%p, src=%p, len=%zu) about to cross allocation boundary",
           (void *)message, (const void *)payload, declared);
  memcpy(message, payload, declared);
  SMS_LOGE("OOB WRITE completed | aborting SMS worker before corrupted heap is reused");
  raise(SIGABRT);
  return -1;
}
