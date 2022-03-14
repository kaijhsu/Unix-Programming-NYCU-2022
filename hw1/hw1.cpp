#include <iostream>
#include <filesystem>
#include <vector>
#include <regex>
#include <stdio.h>
#include <fstream>
#include <pwd.h>
#include <sys/stat.h>

using namespace std;

struct Process{
    string pid;
    string cmd;
    string usr;
    string fd;
    string type;
    string node;
    string name;
};

class Lsof{
public:
    Lsof(){

    }

    void run(){

    }

    string find_cmd(const string &pid_path){
        string path = pid_path+"/comm";
        ifstream file(path);
        string cmd;
        getline (file, cmd);
        file.close();
        return cmd;
    }

    string find_pid(const string &pid_path){
        regex reg("/proc/([0-9]*)");
        smatch m;
        regex_search(pid_path, m, reg);
        return m[1];
    }

    string find_name(const string &pid_path){
        string path = pid_path+"/status";
        ifstream file(path);
        string line;
        string name;

        regex reg("Uid:\t([0-9]*)");
        smatch m;
        while( getline(file, line) ){
            if( regex_search(line, m, reg) ){
                name = uid_to_name(m[1]);
                break;
            }
        }
        file.close();
        return name;
    }

    string uid_to_name(const string &uid_str){
        string name;
        uid_t uid = stoi(uid_str);
        struct passwd *pw;
        pw = getpwuid(uid);
        if(pw){
            return pw->pw_name;
        }
        perror("uid_to_name: getpwuid failed!");
        exit(1);
        return name;
    }

    //pid_path: /proc/4880, name is to get symbol link name
    //return inode number if success, else -1 indicate that permission deny
    int get_cwd(const string &pid_path, string &name, string &type){
        string path = pid_path+"/cwd";
        struct stat buf;

        int flag = stat(path.c_str(), &buf);
        if(flag != 0){
            name = path + " (Permission denied)";
            type = "unknown";
            return -1;
        }
        name = filesystem::read_symlink(path);
        type = get_type(buf);
        return buf.st_ino;
    }

    int get_root(const string &pid_path, string &name, string &type){
        string path = pid_path+"/root";
        struct stat buf;

        int flag = stat(path.c_str(), &buf);
        if(flag != 0){
            name = path + " (Permission denied)";
            type = "unknown";
            return -1;
        }
        name = filesystem::read_symlink(path);
        type = get_type(buf);
        return buf.st_ino;
    }

    int get_exe(const string &pid_path, string &name, string &type){
        string path = pid_path+"/exe";
        struct stat buf;

        int flag = stat(path.c_str(), &buf);
        if(flag != 0){
            name = path + " (Permission denied)";
            type = "unknown";
            return -1;
        }
        name = filesystem::read_symlink(path);
        type = get_type(buf);
        return buf.st_ino;
    }

    bool get_pids(){
        string procPath = "/proc";
        regex reg("/proc/([0-9]*)");
        smatch m;
        for (const auto & entry : filesystem::directory_iterator(procPath)){
            string path = entry.path();
            if( regex_search(path, m, reg) ){
                pid_paths.push_back(path);
            }
        }
        return 0;
    }

    void run_test(){
        cout << "---- Testing Start ----\n";
        find_pid_test();
        find_cmd_test();
        uid_to_name_test();
        find_name_test();
        get_cwd_test();
        get_root_test();
        get_exe_test();
        cout << "---- All test end  ----\n";
    }

    void find_pid_test(){
        cout << "    find_pid_test:\n";
        vector<string> path{"/proc/1", "/proc/2"};
        for(int i=0; i<int(path.size()); ++i){
            string result = find_pid(path[i]);
            printf("        input: %s, result: %s\n", path[i].c_str(), result.c_str());
        }
    }

    void find_cmd_test(){
        cout << "    find_cmd_test:\n";
        vector<string> path({"/proc/1","/proc/2"});
        for(int i=0; i<int(path.size()); ++i){
            string result = find_cmd(path[i]);
            printf("        input: %s, result: %s\n", path[i].c_str(), result.c_str());
        }
    }

    void uid_to_name_test(){
        cout << "    uid_to_name_test:\n";
        vector<string> uid_str{"0", "1000"};
        for(int i=0; i<int(uid_str.size()); ++i){
            string result = uid_to_name(uid_str[i]);
            printf("        input: %s, result: %s\n", uid_str[i].c_str(), result.c_str());
        }
    }

    void find_name_test(){
        cout << "    find_name_test:\n";
        vector<string> path({"/proc/1","/proc/2"});
        for(int i=0; i<int(path.size()); ++i){
            string result = find_name(path[i]);
            printf("        input: %s, result: %s\n", path[i].c_str(), result.c_str());
        }
    }
    
    void get_cwd_test(){
        cout << "    get_cwd_test:\n";
        vector<string> path({"/proc/1","/proc/2","/proc/4880"});
        for(int i=0; i<int(path.size()); ++i){
            string name;
            string type;
            int inode = get_cwd(path[i], name, type);
            printf("        input: %s, inode: %d, name:%s, type:%s\n", path[i].c_str(), inode, name.c_str(), type.c_str());
        }
    }

    void get_root_test(){
        cout << "    get_root_test:\n";
        vector<string> path({"/proc/1","/proc/2","/proc/4880"});
        for(int i=0; i<int(path.size()); ++i){
            string name;
            string type;
            int inode = get_root(path[i], name, type);
            printf("        input: %s, inode: %d, name:%s, type:%s\n", path[i].c_str(), inode, name.c_str(), type.c_str());
        }
    }

    void get_exe_test(){
        cout << "    get_exe_test:\n";
        vector<string> path({"/proc/1","/proc/2","/proc/4880"});
        for(int i=0; i<int(path.size()); ++i){
            string name;
            string type;
            int inode = get_exe(path[i], name, type);
            printf("        input: %s, inode: %d, name:%s, type:%s\n", path[i].c_str(), inode, name.c_str(), type.c_str());
        }
    }

private:
    string get_type(struct stat &buf){
        if(S_ISDIR(buf.st_mode))
            return "DIR";
        if(S_ISREG(buf.st_mode))
            return "REG";
        if(S_ISCHR(buf.st_mode))
            return "CHR";
        if(S_ISFIFO(buf.st_mode))
            return "FIFO";
        if(S_ISSOCK(buf.st_mode))
            return "SOCK";
        return "unknown";
            
    }

    vector<string> pid_paths;
    vector<Process> processes;
};


int main(int argc, char *argv[]){
    Lsof lsof;
    lsof.run_test();
    return 0;
}
