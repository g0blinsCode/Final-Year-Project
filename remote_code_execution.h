#include <iostream>
#include <string>
#include "headers.h"
void RCE_Detector(char* payload, const std::vector<std::string>& rce_payloads) {
    for (const std::string& str : rce_payloads) {
        // Get a pointer to the character array represented by the string
        const char* str_ptr = str.c_str();

        // Search for the string in the payload
        if (strstr(payload, str_ptr) != NULL) {
            // The string was found in the payload
        printf("WARNING: RCE payload detected! and payload is == %s", payload, "\n");
            // sleep(1);
            
            FILE *fp;
            fp = fopen("rce_output.txt", "a");
            fprintf(fp, "%s", payload);
            fclose(fp);        
            exit(0);
        }
    }
}
// if (payload.find("include") != std::string::npos ||
//       payload.find("require") != std::string::npos ||
//       payload.find("readfile") != std::string::npos ||
//       payload.find("file_get_contents") != std::string::npos) {
//     std::cout << "WARNING: File inclusion payload detected!" << std::endl;
//     sleep(5);
//   }

  // Check for code injection rce_payloads
//   if (payload.find("eval") != std::string::npos ||
//       payload.find("exec") != std::string::npos ||
//       payload.find("system") != std::string::npos ||
//       payload.find("passthru") != std::string::npos) {
//     std::cout << "WARNING: Remote Code Execution Attack Detected !" << std::endl;
//     sleep(5);
//   }


//   vector<string> words;
//   string word = "";
//   for (int i = 0; i < strlen(payload); i++) {
//     if (payload[i] == ' ' || payload[i] == '\n' || payload[i] == '\t' || payload[i] == '\r') {
//       if (word != "") words.push_back(word);
//       word = "";
//     } else {
//       word += payload[i];
//     }
//   }
//   if (word != "") words.push_back(word);

  // Check for the presence of rce_payloads
//   for (int i = 0; i < words.size(); i++) {
//     if (binary_search(rce_payloads.begin(), rce_payloads.end(), words[i])) {
    //   printf("WARNING: Remote Code Execution Attack == %s\n", words[i].c_str());
    //   exit(0);
    // sleep(5);
    // }
//   }
// }

