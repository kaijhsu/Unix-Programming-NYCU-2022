#include <iostream>
#include <string>
#include <vector>
#include <string.h>
#include <sdb.hpp>
#include <utility.hpp>

using namespace std;

int state = NOT_LOADED;
string tracee_program;

void load() {
    cout << "not imp load yet!\n";
}

void parse_input(vector<string> &inputs){
    if (inputs.size() < 1) return ;
    
    string cmd = inputs[0];
    
    if (cmd == "break" or cmd == "b"){
        cout << "break\n";
    }
    else if (cmd == "cont" or cmd == "c"){
        cout << "cont\n";
    }
    else if (cmd == "delete"){
        cout << "delete\n";    
    }  
    else if (cmd == "disasm" or cmd == "d"){
        cout << "disasm\n";
    } 
    else if (cmd == "dump" or cmd == "x"){
        cout << "dump\n";
    }
    else if (cmd == "exit" or cmd == "q"){
        cout << "quit\n";
    }
    else if (cmd == "get" or cmd == "g"){
        cout << "get\n";
    }
    else if (cmd == "getregs"){
        cout << "getregs\n";
    }
    else if (cmd == "help" or cmd == "h"){
        cout << "help\n";
    }
    else if (cmd == "list" or cmd == "l"){
        cout << "list\n";
    }
    else if (cmd == "load"){
        cout << "load\n";
    }
    else if (cmd == "run" or cmd == "r"){
        cout << "run\n";
    }
    else if (cmd == "vmmap" or cmd == "m"){
        cout << "vmmap\n";
    }
    else {
        cout << "unknown cmd\n";
    }
}

int main(int argc, char *argv[]){

    if (argc > 1) {
        tracee_program = argv[1];
        load(); 
    }

    while (true) {
        cerr << "sdb> ";
        string line;
        getline(cin, line);
        vector<string> inputs = split(line);
        parse_input(inputs);
    }
    return 0;
}