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


// "confirm"

// HTML encoding: "&confirm;"
// URL encoding: "%63%6f%6e%66%69%72%6d"
// Base64 encoding: "Y29uZmlybQ=="
// Hex encoding: "636f6e6669726d"
// ASCII encoding: "\x63\x6f\x6e\x66\x69\x72\x6d"
// "alert"

// HTML encoding: "&alert;"
// URL encoding: "%61%6c%65%72%74"
// Base64 encoding: "YWxlcnQ="
// Hex encoding: "616c657274"
// ASCII encoding: "\x61\x6c\x65\x72\x74"
    if (strstr(payload, "<script>") != NULL || strstr(payload, "</>") != NULL ||
        strstr(payload, "&lt;script&gt;") != NULL || strstr(payload, "&lt;/script&gt;") != NULL ||
        strstr(payload, "%3Cscript%3E") != NULL || strstr(payload, "%3C/script%3E") != NULL ||
        strstr(payload, "&lt;script&gt;") ||
        strstr(payload, "PHNjcmlwdD4=") != NULL || strstr(payload, "PHNjcmlwdD4K") != NULL ||
        strstr(payload, "3c7363726970743e") != NULL || strstr(payload, "3c2f7363726970743e") != NULL ||
        strstr(payload, "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e") != NULL ||
        strstr(payload, "\x3c\x2f\x73\x63\x72\x69\x70\x74\x3e") != NULL
        ||strstr(payload, "&lt;script&gt;") != NULL ||strstr(payload, "%3Cscript%3E") != NULL||
        strstr(payload, "PHNjcmlwdD4=") != NULL ||strstr(payload, "3c7363726970743e") != NULL 
        ||strstr(payload, "\\x3c\\x73\\x63\\x72\\x69\\x70\\x74\\x3e") != NULL||strstr(payload, "<script>") != NULL
        ||strstr(payload, "&alert;") != NULL||strstr(payload, "%61%6c%65%72%74") != NULL
        ||strstr(payload, "YWxlcnQ=") != NULL||strstr(payload, "616c657274") != NULL
        ||strstr(payload, "/x61\x6c\x65\x72\x74") != NULL)
    {
        printf("WARNING: XSS payload detected! and payload is == %s", payload, "\n");
        sleep(5);
    }
}


#endif
