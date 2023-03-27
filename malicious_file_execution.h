#include "csrf_detector.h"
#include "headers.h"
#include "xss_detector.h"

// Malicious file execution detection function
void Malicious_File_Execution_Detector(char *payload) {
  // Check for the presence of malicious file execution payloads in the packet payload
  if (strstr(payload, ".exe") != NULL || strstr(payload, ".bat") != NULL || strstr(payload, ".cmd") != NULL ||
      strstr(payload, ".vbs") != NULL || strstr(payload, ".js") != NULL || strstr(payload, ".php") != NULL ||
      strstr(payload, ".py") != NULL) {
    printf("WARNING: Malicious file execution payload detected!\n");
             FILE *fp;
            fp = fopen("mfe_output.txt", "a");
            fprintf(fp, "%s", payload);
            fclose(fp);   
            exit(0);
  
  }
}