#ifndef xss_detector_h
#define xss_detector_h
#include "headers.h"

void XSS_Detector(char* payload, const std::vector<std::string>& xss_payloads)
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
    for (const std::string& str : xss_payloads) {
        // Get a pointer to the character array represented by the string
        const char* str_ptr = str.c_str();

        // Search for the string in the payload
        if (strstr(payload, str_ptr) != NULL) {
            // The string was found in the payload
        printf("WARNING: XSS payload detected! and payload is == %s", payload, "\n");
            sleep(5);
             FILE *fp;
    fp = fopen("xss_output.txt", "a");
    fprintf(fp, "%s", payload);
    fclose(fp);
    sleep(5);
        }
    }
 }


#endif
