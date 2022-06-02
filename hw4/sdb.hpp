#pragma once

#include <string>
#include <vector>
#include <map>

#define NOT_LOADED 0
#define LOADED     1
#define RUNNING    2


using namespace std;

struct Breakpoint {
    unsigned long long address;
    unsigned char code;
};

map<string, unsigned long long *> get_regs_map();

void dump(unsigned long long);
void delete_breakpoint(int);
void si_breakpoint();
void cont();
void list();
void reset_breakpoint(Breakpoint breakpoint);
unsigned long long peek_original_code(unsigned long long address);
unsigned long long patch_opcode(unsigned long long code, unsigned long long segement);
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