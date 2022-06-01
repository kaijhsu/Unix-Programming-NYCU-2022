#pragma once

#include <string>
#include <vector>
#include <map>

#define NOT_LOADED 0
#define LOADED 1
#define RUNNING 2

using namespace std;

struct breakpoint {
    unsigned long long address;
    unsigned char code;
};

map<string, unsigned long long *> get_regs_map();
void disasm(unsigned long long target_address);
unsigned long long disasm_one(unsigned long long target_address);
void check_status();
void run();
void quit();
void set(const string &target, const unsigned long long &value);
void si();
void getregs();
void get(const string &target);
void vmmap();
void start();
void load();
void help();
void parse_input(vector<string> &inputs);