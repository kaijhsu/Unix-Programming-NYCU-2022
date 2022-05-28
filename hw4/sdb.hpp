#pragma once

#include <string>
#include <vector>

#define NOT_LOADED 0
#define LOADED 1
#define RUNNING 2

using namespace std;

void load();
void parse_input(vector<string> &inputs);