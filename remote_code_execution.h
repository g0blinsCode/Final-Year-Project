#ifndef rce_detector_h
#define rce_detector_h
#include "headers.h"

bool check_rce_payload(string data_payload, string payload) {
    size_t found = data_payload.find(payload);
    if (found != string::npos) {
        return true;
    }
    return false;
}

void RCE_Detector(char *data_payload, char *source_ip , char* destination_ip){

    string file_name = "rce_payload.txt";
    ifstream infile(file_name);
    string payload;

    if (!infile) {
        cout << "Error opening file: " << file_name << endl;
    }

    while (getline(infile, payload)) {
        if (check_rce_payload(data_payload, payload)) {
            cout<<"\n RCE Payload Detected ....";
            cout << "\nPayload >> " << payload << " << found in data payload." << endl;
            string str = " RCE Payload Detected .... Payload is >> " + payload + " << found in data payload Source IP attacking is  >> " + source_ip + " << and Destination IP is >> " + destination_ip + " << ";
            Output1(str);
            // exit(0);
            // exit(0);
        }
    }

    infile.close();
}
#endif
