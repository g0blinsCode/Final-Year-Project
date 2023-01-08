#ifndef xss_detector_h
#define xss_detector_h
#include "headers.h"


void XSS_Detector(char *payload)
{
    // Check for the presence of XSS payloads in the packet payload

    /*
        HTML encoding: "&lt;script&gt;"
    URL encoding: "%3Cscript%3E"
    Base64 encoding: "PHNjcmlwdD4="
    Hex encoding: "3c7363726970743e"
    ASCII encoding: "\x3c\x73\x63\x72\x69\x70\x74\x3e"*/

    if (strstr(payload, "<script>") != NULL || strstr(payload, "</script>") != NULL ||
        strstr(payload, "&lt;script&gt;") != NULL || strstr(payload, "&lt;/script&gt;") != NULL ||
        strstr(payload, "%3Cscript%3E") != NULL || strstr(payload, "%3C/script%3E") != NULL ||
        strstr(payload, "&lt;script&gt;") ||
        strstr(payload, "PHNjcmlwdD4=") != NULL || strstr(payload, "PHNjcmlwdD4K") != NULL ||
        strstr(payload, "3c7363726970743e") != NULL || strstr(payload, "3c2f7363726970743e") != NULL ||
        strstr(payload, "\x3c\x73\x63\x72\x69\x70\x74\x3e") != NULL ||
        strstr(payload, "\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e") != NULL)
    {
        printf("WARNING: XSS payload detected! and payload is == %s", payload, "\n");
        exit(0);
    }
}


#endif
