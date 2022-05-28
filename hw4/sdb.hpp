#pragma once

#include <string>
#include <vector>
#include <map>

#define NOT_LOADED 0
#define LOADED 1
#define RUNNING 2

using namespace std;

map<string, unsigned long long> get_regs_map();
void getregs();
void get(const string &target);
void vmmap();
void start();
void load();
void help();
void parse_input(vector<string> &inputs);