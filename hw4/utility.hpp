#pragma once 

#include <vector>
#include <string>
#include <iostream>
#include <sstream>
#include <utility.hpp>


using namespace std;

vector<string> split(const string &line, const char delim = '\0'){
    vector<string> ret;
    stringstream ss(line);
    string word;
    if (delim){
        while (getline(ss, word, delim)){
            ret.push_back(word);
        } 
    }
    else {
        while (ss >> word){
            ret.push_back(word);
        }
    }
    return ret;
}

void errquit(string message){
    cerr << "** ERROR QUIT: " << message << "\n";
    exit(-1);
}

unsigned long long strtoull(const string &s){
    int base = 10;
    if( s.size() >= 2 and (s.substr(0,2) == "0x" or s.substr(0,2) == "0X") ) base = 16;
    return stoull(s, NULL, base);
}