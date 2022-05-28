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
    cerr << "ERROR QUIT: " << message << "\n";
    exit(-1);
}