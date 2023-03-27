#ifndef OUTPUT_H
#define OUTPUT_H

#include <fstream>
#include <iostream>
#include <string>

using namespace std;
void Output1(string str) {
    string filename = "output.txt";
    ofstream outfile;

    // Check if the file exists
    ifstream infile(filename.c_str());
    if (infile.good()) {
        // Check if the string is already in the file
        string line;
        while (getline(infile, line)) {
            if (line == str) {
                return; // Exit the function without writing
            }
        }

        // Open the file in append mode
        outfile.open(filename.c_str(), ios::app);
    } else {
        // Create the file and open it in write mode
        outfile.open(filename.c_str());
    }

    // Write to the file
    outfile << str << "\n";

    // Close the file
    outfile.close();
}


#endif
