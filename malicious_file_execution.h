#ifndef mfe_detector_h
#define mfe_detector_h
#include "headers.h"

bool check_mfe_payload(string data_payload, string payload) {
    size_t found = data_payload.find(payload);
    if (found != string::npos) {
        return true;
    }
    return false;
}

void MaliciousFileExecution_Detector(char *data_payload , char *source_ip , char* destination_ip){

    string file_name = "mfe_payload.txt";
    ifstream infile(file_name);
    string payload;

    if (!infile) {
        cout << "Error opening file: " << file_name << endl;
    }

    while (getline(infile, payload)) {
        if (check_mfe_payload(data_payload, payload)) {
            cout<<"\n Malicious File Execution Payload Detected ....";
            cout << "\nPayload  >> " << payload << " << found in data payload." << endl;
            string str = " MFE Payload Detected .... Payload is >> " + payload + " << found in data payload Source IP attacking is  >> " + source_ip + " << and Destination IP is >> " + destination_ip + " << ";
            Output1(str);
            // exit(0);
        }
    }

    infile.close();
}
#endif
