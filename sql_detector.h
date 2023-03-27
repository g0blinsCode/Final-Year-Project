#ifndef sql_detector_h
#define sql_detector_h
#include "headers.h"

bool check_sql_payload(string data_payload, string payload) {
    size_t found = data_payload.find(payload);
    if (found != string::npos) {
        return true;
    }
    return false;
}

void SQL_Detector(char *data_payload){

    string file_name = "sql_payload.txt";
    ifstream infile(file_name);
    string payload;

    if (!infile) {
        cout << "Error opening file: " << file_name << endl;
    }

    while (getline(infile, payload)) {
        if (check_sql_payload(data_payload, payload)) {
            cout<<"\n SQL Payload Detected ....";
            cout << "\nPayload >> " << payload << " << found in data payload." << endl;
            // exit(0);
        }
    }

    infile.close();
}
#endif
