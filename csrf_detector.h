#ifndef CSRF_DETECTOR_H
#define CSRF_DETECTOR_H
#include "headers.h"

void CSRF_Detector(char *payload) {
  // Check for the presence of CSRF payloads in the packet payload
  if (strstr(payload, "csrf_token") != NULL || strstr(payload, "csrf-token") != NULL) {
    printf("WARNING: CSRF payload detected!\n");
  }
}

#endif
