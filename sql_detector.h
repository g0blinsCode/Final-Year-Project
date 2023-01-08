#include "csrf_detector.h"
#include "headers.h"
#include "xss_detector.h"


// SQL injection detection function
void SQL_Detector(char *payload, vector<string> &payloads) {
  // Split the payload into words
  vector<string> words;
  string word = "";
  for (int i = 0; i < strlen(payload); i++) {
    if (payload[i] == ' ' || payload[i] == '\n' || payload[i] == '\t' || payload[i] == '\r') {
      if (word != "") words.push_back(word);
      word = "";
    } else {
      word += payload[i];
    }
  }
  if (word != "") words.push_back(word);

  // Check for the presence of payloads
  for (int i = 0; i < words.size(); i++) {
    if (binary_search(payloads.begin(), payloads.end(), words[i])) {
      printf("WARNING: SQL injection payload detected! payload == %s\n", words[i].c_str());
    //   exit(0);
    sleep(5);
    }
  }
}