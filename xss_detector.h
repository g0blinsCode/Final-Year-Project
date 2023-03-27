#ifndef xss_detector_h
#define xss_detector_h
#include "headers.h"

bool check_xss_payload(string data_payload, string payload) {
    size_t found = data_payload.find(payload);
    if (found != string::npos) {
        return true;
    }
    return false;
}

void XSS_Detector(char *data_payload , char *source_ip , char* destination_ip){

    string file_name = "xss_payload.txt";
    ifstream infile(file_name);
    string payload;

    if (!infile) {
        cout << "Error opening file: " << file_name << endl;
    }

    while (getline(infile, payload)) {
        if (check_xss_payload(data_payload, payload)) {
            cout<<"\n XSS Payload Detected ....";
            cout << "\nPayload  >> " << payload << " << found in data payload." << endl;
            string str = " XSS Payload Detected .... Payload is >> " + payload + " << found in data payload Source IP attacking is  >> " + source_ip + " << and Destination IP is >> " + destination_ip + " << ";
            Output1(str);
            // exit(0);
        }
    }

    infile.close();
}
#endif
