#include "csrf_detector.h"
#include "headers.h"
#include "xss_detector.h"


// Clickjacking detection function
void Clickjacking_Detector(char *payload) {
  // Check for the presence of clickjacking payloads in the packet payload
  if (strstr(payload, "clickjacking") != NULL) {
    printf("WARNING: Clickjacking payload detected!\n");
  }
}