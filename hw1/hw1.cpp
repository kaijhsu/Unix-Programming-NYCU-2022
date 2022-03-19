#include <iostream>
#include <filesystem>
#include <vector>
#include <regex>
#include <stdio.h>
#include <fstream>
#include <pwd.h>
#include <sys/stat.h>
#include <set>
#include <unistd.h>

using namespace std;


class Lsof{
public:
    Lsof(){

    }

    void run(){
        printf("COMMAND\t\t\tPID\t\t\tUSER\t\t\tFD\t\t\tTYPE\t\t\tNODE\t\t\tNAME\n");

        get_pids();
        string line_format = "%s\t\t\t%s\t\t\t%s\t\t\t%s\t\t\t%s\t\t\t%s\t\t\t%s\n";
        for(auto &pid_path : pid_paths){
            string command = find_cmd(pid_path);
            if(command == "")
                continue;
            if( cmd_reg  != ""){
                regex reg(cmd_reg);
                smatch m;
                if(!regex_search(command, m, reg))
                    continue;
            }
            string pid = find_pid(pid_path);
            string user = find_user(pid_path);
            string name="", type="";
            
            //print cwd
            string inode = to_string(get_cwd(pid_path, name, type));
            if(inode == "-1") inode = "";
            string cmd_fd = "cwd";
            filter_print(line_format, command, pid, user, cmd_fd, type, inode, name);
            
            //print root
            inode = to_string(get_root(pid_path, name, type));
            if(inode == "-1") inode = "";
            string root_fd = "rtd";
            filter_print(line_format, command, pid, user, root_fd, type, inode, name);

            //print exe
            inode = to_string(get_exe(pid_path, name, type));
            if(inode == "-1") inode = "";
            string exe_fd = "txt";
            filter_print(line_format, command, pid, user, exe_fd, type, inode, name);

            //get fd
            vector<string> fd_fds, fd_types, fd_nodes, fd_names;
            int fd_flag = get_fd(pid_path, fd_fds, fd_types, fd_nodes, fd_names);
            if(fd_flag == 0){
                vector<string> maps_fds, maps_inodes, maps_names;
                get_maps(pid_path, maps_fds, maps_inodes, maps_names);
                string fd_type = "REG";
                for(size_t i=0; i<maps_inodes.size(); ++i)
                    filter_print(line_format, command, pid, user, maps_fds[i], fd_type, maps_inodes[i], maps_names[i]);
            }

            //print fd
            for(size_t i=0; i<fd_fds.size(); ++i)
                filter_print(line_format, command, pid, user, fd_fds[i], fd_types[i], fd_nodes[i], fd_names[i]);
        }
    }

    bool set_reg(const string &cmd_reg, const string &type_reg, const string &file_reg){
        set<string> valid_types {"REG", "CHR", "DIR", "FIFO", "SOCK", "unknown", ""};
        if(!valid_types.count(type_reg))
            return false;
        this->cmd_reg = cmd_reg;
        this->type_reg = type_reg;
        this->file_reg = file_reg;
        return true;
    }

    string find_cmd(const string &pid_path){
        string path = pid_path+"/comm";
        ifstream file(path);
        string cmd = "";
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

    string find_user(const string &pid_path){
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

    int get_maps(const string &pid_path, vector<string> &fds, vector<string> &inodes, vector<string> &fileNames){
        string path = pid_path + "/maps";
        ifstream file(path);
        if(!file)
            return -1;
        string line;
        regex reg("[0-9a-zA-Z-]+ [rwxps-]+ [0-9a-zA-Z]+ [0-9:A-z]+ ([0-9]+)[ \t]+([^ ]+)");
        smatch m;
        regex del_reg("deleted");
        smatch del_m;

        set<string> mySet;
        while( getline(file, line) ){
            if( regex_search(line, m, reg) ){
                string inode = m[1];
                string name = m[2];
                if(inode == "0")
                    continue;
                if(mySet.count(inode))
                    continue;
                int del_flag = regex_search(line, del_m, del_reg);
                if(del_flag)
                    fds.push_back("DEL");
                else
                    fds.push_back("mem");
                mySet.insert(inode);
                inodes.push_back(inode);
                fileNames.push_back(name);
            }
        }
        return 0;
    }

    int get_fd(const string &pid_path, vector<string> &fds, vector<string> &types, vector<string> &nodes, vector<string> &names){
        string path = pid_path + "/fd";
        filesystem::directory_iterator directory;
        try{
            directory = filesystem::directory_iterator(path);
        }
        catch(filesystem::filesystem_error &e){
            fds.push_back("NOFD");
            types.push_back("");
            nodes.push_back("");
            names.push_back(path+" (Permission denied)");
            return -1;
        }
        for(const auto &entry : directory){
            if(!entry.is_symlink())
                continue;
            if(!entry.exists()){
                cout << "entry not exist!\n";
                continue;
            }
            struct stat st;
            struct stat lst;
            if( stat(entry.path().c_str(), &st) == -1){
                cout << entry.path() << " stat fail!\n";
                continue;
            };
            if( lstat(entry.path().c_str(), &lst) == -1){
                cout << entry.path() << " lstat fail!\n";
                continue;
            };

            string name = filesystem::read_symlink(entry.path());
            string type = get_type(st);
            string node = to_string(st.st_ino);         

            regex reg("\/proc\/[0-9]+\/fd\/([0-9]+)");
            smatch m;
            string pathName(entry.path().c_str());
            regex_search(pathName, m, reg);
            string fd = m[1];
            if(lst.st_mode & S_IRUSR and lst.st_mode & S_IWUSR)
                fd += "u";
            else if(lst.st_mode & S_IWUSR)
                fd += "w";
            else if(lst.st_mode & S_IRUSR)
                fd += "r";

            names.push_back(name);
            types.push_back(type);
            nodes.push_back(node);
            fds.push_back(fd);
        }
        return 0;
    }

    bool get_pids(){
        string procPath = "/proc";
        regex reg("[0-9]+");
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
        find_user_test();
        get_cwd_test();
        get_root_test();
        get_exe_test();
        get_maps_test();
        get_fd_test();
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

    void find_user_test(){
        cout << "    find_user_test:\n";
        vector<string> path({"/proc/1","/proc/2"});
        for(int i=0; i<int(path.size()); ++i){
            string result = find_user(path[i]);
            printf("        input: %s, result: %s\n", path[i].c_str(), result.c_str());
        }
    }
    
    void get_cwd_test(){
        cout << "    get_cwd_test:\n";
        vector<string> path({"/proc/1","/proc/2"});
        for(int i=0; i<int(path.size()); ++i){
            string name;
            string type;
            int inode = get_cwd(path[i], name, type);
            printf("        input: %s, inode: %d, name:%s, type:%s\n", path[i].c_str(), inode, name.c_str(), type.c_str());
        }
    }

    void get_root_test(){
        cout << "    get_root_test:\n";
        vector<string> path({"/proc/1","/proc/2"});
        for(int i=0; i<int(path.size()); ++i){
            string name;
            string type;
            int inode = get_root(path[i], name, type);
            printf("        input: %s, inode: %d, name:%s, type:%s\n", path[i].c_str(), inode, name.c_str(), type.c_str());
        }
    }

    void get_exe_test(){
        cout << "    get_exe_test:\n";
        vector<string> path({"/proc/1","/proc/2"});
        for(int i=0; i<int(path.size()); ++i){
            string name;
            string type;
            int inode = get_exe(path[i], name, type);
            printf("        input: %s, inode: %d, name:%s, type:%s\n", path[i].c_str(), inode, name.c_str(), type.c_str());
        }
    }

    void get_maps_test(){
        cout << "    get_maps_test:\n";
        vector<string> path({"/proc/1", "/proc/12199"});
        for(int i=0; i<int(path.size()); ++i){
            vector<string> inodes;
            vector<string> fileNames;
            vector<string> fds;
            get_maps(path[i], fds, inodes, fileNames);
            printf("        input: %s\n", path[i].c_str());
            for(__SIZE_TYPE__ j=0; j<inodes.size(); ++j){
                printf("            fds: %s, inode: %s, file: %s\n", fds[j].c_str(), inodes[j].c_str(), fileNames[j].c_str());
            }
        }
    }

    void get_fd_test(){
        cout << "    get_fd_test:\n";
        vector<string> path({"/proc/1", "/proc/29254"});
        for(int i=0; i<int(path.size()); ++i){
            vector<string> fds, types, nodes, names;
            printf("        input: %s\n", path[i].c_str());
            get_fd(path[i],fds,types,nodes,names);
            for(size_t j=0; j<fds.size(); ++j)
                printf("            fd: %s, type: %s, node: %s, name: %s\n", fds[j].c_str(), types[j].c_str(), nodes[j].c_str(), names[j].c_str());
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

    int filter_print(string &format, string &cmd, string &pid, string &user, string &fd, string &type, string &inode, string &name){
        if(type_reg != ""){
            if(type != type_reg)
                return 0;
        }
        if(file_reg != ""){
            regex reg(file_reg);
            smatch m;
            if( regex_search(name, m, reg) == 0)
                return 0;
        }
        printf(format.c_str(), cmd.c_str(), pid.c_str(), user.c_str(), fd.c_str(), type.c_str(), inode.c_str(), name.c_str());
        return 1;
    }

    vector<string> pid_paths;
    string cmd_reg = "";
    string type_reg = "";
    string file_reg = "";
};


int main(int argc, char *argv[]){
    //parse argument
    string cmd_reg = "";
    string type_reg = "";
    string file_reg = "";
    int o;
    while( (o = getopt(argc, argv, "c:t:f:")) != -1 ){
        switch (o) {
            case 'c':
                cmd_reg = optarg;
                break;
            case 't':
                type_reg = optarg;
                break;
            case 'f':
                file_reg = optarg;
                break;
            case '?':
                exit(-1);
                return -1;
                break;
            default:
                break;
        }
    }
    Lsof lsof;
    if( lsof.set_reg(cmd_reg, type_reg, file_reg) == false ){
        cerr << "Invalid TYPE option.\n";
        exit(-1);
    }
    // lsof.run_test();
    lsof.run();

    return 0;
}
