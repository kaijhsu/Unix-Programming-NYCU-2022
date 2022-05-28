#include <iostream>
#include <string>
#include <vector>
#include <map>
#include <iomanip>
#include <string.h>
#include <unistd.h>
#include <assert.h> 
#include <stdlib.h>
#include <fstream>
#include <sys/wait.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sdb.hpp>
#include <utility.hpp>

using namespace std;

int state = NOT_LOADED;


pid_t tracee_pid = 0;
string tracee_program = "";
struct user_regs_struct tracee_regs;
unsigned long long entry_point;

void help() {
    cerr << "- break {instruction-address}: add a break point\n";
    cerr << "- cont: continue execution\n";
    cerr << "- delete {break-point-id}: remove a break point\n";
    cerr << "- disasm addr: disassemble instructions in a file or a memory region\n";
    cerr << "- dump addr: dump memory content\n";
    cerr << "- exit: terminate the debugger\n";
    cerr << "- get reg: get a single value from a register\n";
    cerr << "- getregs: show registers\n";
    cerr << "- help: show this message\n";
    cerr << "- list: list break points\n";
    cerr << "- load {path/to/a/program}: load a program\n";
    cerr << "- run: run the program\n";
    cerr << "- vmmap: show memory layout\n";
    cerr << "- set reg val: get a single value to a register\n";
    cerr << "- si: step into instruction\n";
    cerr << "- start: start the program and stop at the first instruction\n";
    return ;
}

void quit(){
    if (tracee_pid){
        kill(tracee_pid, SIGTERM);
    }
    exit(0);
}

void set(const string &target, const unsigned long long &value){
    if (state != RUNNING) {
        cerr << "** State must be RUNNING.\n" << endl;
        return;
    }
    map<string, unsigned long long *> regs_map = get_regs_map();
    if (regs_map.find(target) == regs_map.end()){
        cerr << "** No such register.\n";
        return;
    }
    *(regs_map[target]) = value;
    ptrace(PTRACE_SETREGS, tracee_pid, NULL, &tracee_regs);
}

void si(){
    if (state != RUNNING){
        cerr << "** State must be RUNNING.\n";
        return;
    }
    ptrace(PTRACE_SINGLESTEP, tracee_pid, NULL, NULL);
}

map<string, unsigned long long *> get_regs_map(){
    map<string, unsigned long long *> regs_map;

    ptrace(PTRACE_GETREGS, tracee_pid, 0, &tracee_regs);
    regs_map["rax"] = (unsigned long long *) &tracee_regs.rax;
    regs_map["rbx"] = (unsigned long long *) &tracee_regs.rbx;
    regs_map["rcx"] = (unsigned long long *) &tracee_regs.rcx;
    regs_map["rdx"] = (unsigned long long *) &tracee_regs.rdx;
    regs_map["r8"] = (unsigned long long *) &tracee_regs.r8;
    regs_map["r9"] = (unsigned long long *) &tracee_regs.r9;
    regs_map["r10"] = (unsigned long long *) &tracee_regs.r10;
    regs_map["r11"] = (unsigned long long *) &tracee_regs.r11;
    regs_map["r12"] = (unsigned long long *) &tracee_regs.r12;
    regs_map["r13"] = (unsigned long long *) &tracee_regs.r13;
    regs_map["r14"] = (unsigned long long *) &tracee_regs.r14;
    regs_map["r15"] = (unsigned long long *) &tracee_regs.r15;
    regs_map["rdi"] = (unsigned long long *) &tracee_regs.rdi;
    regs_map["rsi"] = (unsigned long long *) &tracee_regs.rsi;
    regs_map["rbp"] = (unsigned long long *) &tracee_regs.rbp;
    regs_map["rsp"] = (unsigned long long *) &tracee_regs.rsp;
    regs_map["rip"] = (unsigned long long *) &tracee_regs.rip;
    regs_map["flags"] = (unsigned long long *) &tracee_regs.eflags;
    
    return regs_map;
}

void get(const string &target) {
    if (state != RUNNING){
        cerr << "** State must be RUNNING.\n";
        return ;
    }

    map<string, unsigned long long *> regs_map = get_regs_map();
    if (regs_map.find(target) == regs_map.end()){
        cerr << "** No such register.\n";
        return ;
    }
    cerr << target << " = " << *(regs_map[target]) << " (0x" << hex << *(regs_map[target]) << dec << ")\n";
}

void getregs() {
    if (state != RUNNING){
        cerr << "** State must be RUNNING.\n";
        return ;
    }
    map<string, unsigned long long *> regs_map = get_regs_map();
    vector<string> regs_sequence{"rax", "rbx", "rcx", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
                                ,"rdi", "rsi", "rbp", "rsp", "rip", "flags"};

    int endl_cnt = 0;
    for(auto &it : regs_sequence){
        endl_cnt++;
        string key = it;
        for(auto &it : key) it = toupper(it);
        cerr << left << setw(3) << key << " ";
        cerr << left << setw(24) << hex << *regs_map[it] << dec << " ";
        if(endl_cnt % 4 == 0) cerr << endl;
    }
    cerr << right << "\n";
    return;
}

void vmmap() {
    if(state != RUNNING){
        cerr << "** state must be RUNNING.\n";
        return;
    }
    ifstream maps_file("/proc/" + to_string(tracee_pid) + "/maps");
    string line;
    while (getline(maps_file, line)){
        vector<string> words = split(line);
        vector<string> addr = split(words[0], '-');
        
        int non_zero = 0;
        while(non_zero < int(words[2].size() - 1) and words[2][non_zero] == '0') non_zero++;

        cerr << setfill('0') << setw(16) << addr[0] << "-"
             << setfill('0') << setw(16) << addr[1] << " "
             << words[1].substr(0,3) << " "
             << words[2].substr(non_zero) << " ";
        if (words.size() > 5) cerr << words[5] << "\n";
    }
    maps_file.close();
    return ;
}

void start() {
    if (state != LOADED){
        cerr << "** state must be LOADED.\n";
        return;
    }
    cerr << "** pid " << tracee_pid << "\n";
    state = RUNNING;
    return;

}

void load() {
    if (state != NOT_LOADED){
        cerr << "** state must be NOT_LOADED.\n";
        return;
    }

    // check tracee_program accessibility
    struct stat st;
    if (stat(tracee_program.c_str(), &st) < 0) errquit("** can't open tracee_program.");
    if ((st.st_mode & S_IEXEC) == 0) errquit("** can't exec tracee_program.");


    if ((tracee_pid = fork()) < 0) errquit("fork");
    if (tracee_pid == 0) {  
        // tracee_pid
        if (ptrace(PTRACE_TRACEME, 0, NULL, NULL) < 0){
            errquit("ptrace tracee_pid traceme");
        }
        execlp(tracee_program.c_str(), tracee_program.c_str(), NULL);
        errquit("execlp");
    } else {
        // parent
        int status;

        // trace child, set option
        if (waitpid(tracee_pid, &status, 0) < 0) errquit("wait");
        assert(WIFSTOPPED(status));
        ptrace(PTRACE_SETOPTIONS, tracee_pid, 0, PTRACE_O_EXITKILL);

        // get entry_point
        struct user_regs_struct regs;
        ptrace(PTRACE_GETREGS, tracee_pid, 0, &regs);
        entry_point = regs.rip;

        cerr << "** program '" << tracee_program << "' loaded. entry point 0x" << hex << entry_point << dec << endl;
        state = LOADED;
    }
    return ;
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
        quit();
    }
    else if (cmd == "get" or cmd == "g"){
        if(inputs.size() < 2){
            cerr << "** usage: get <target_reg>\n";
            return;
        }
        get(inputs[1]);
    }
    else if (cmd == "getregs"){
        getregs();
    }
    else if (cmd == "help" or cmd == "h"){
        help();
    }
    else if (cmd == "list" or cmd == "l"){
        cout << "list\n";
    }
    else if (cmd == "load"){
        if (inputs.size() != 2){
            cerr << "** usage: load <your_program_path>";
            return;
        }
        tracee_program = inputs[1];
        load();
    }
    else if (cmd == "run" or cmd == "r"){
        cout << "run\n";
    }
    else if (cmd == "vmmap" or cmd == "m"){
        vmmap();
    }
    else if (cmd == "set" or cmd == "s"){
        if (inputs.size() < 3){
            cerr << "** usage: set <target_register> <ull value>\n";
            return;
        }
        string target = inputs[1];
        unsigned long long value = strtoull(inputs[2]);
        set(target, value);
    }
    else if (cmd == "si"){
        si();
    }
    else if (cmd == "start"){
        start();
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