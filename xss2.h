#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include "headers.h"

string xss_detect(string packet_payload){

    // Read the contents of sql.txt into a vector of strings
    std::vector<std::string> sql_lines;
    std::ifstream sql_file("sql.txt");
    std::string line;
    while (std::getline(sql_file, line))
    {
        sql_lines.push_back(line);
    }
    sql_file.close();

    // Compare the packet payload with the contents of sql.txt
    bool match_found = false;
    for (const std::string& sql_line : sql_lines)
    {
        if (packet_payload == sql_line)
        {
            match_found = true;
            break;
        }
    }

    // Print the result
    if (match_found)
    {
        std::cout << "warning\n";
        exit(0);
    }
    else
    {
        std::cout << "not matched\n";
    }

}
