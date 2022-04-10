#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>
#include <stdarg.h>
#include <sys/stat.h>
#include <fcntl.h>

static int _stderr_fd = -1;
static FILE * _stderr;

void* _load_function(void *fPtr, const char *name){
    if(_stderr_fd == -1){
        _stderr_fd = dup(STDERR_FILENO);
        _stderr = fdopen(_stderr_fd, "w");
    }
    if(fPtr != NULL)
        return fPtr;

    if(fPtr == NULL){
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            return dlsym(handle, name);
    }
    return NULL;
}


int _convert_fd(int fd, char *path){
    char buf[PATH_MAX];
    snprintf(buf, PATH_MAX, "/proc/self/fd/%d", fd);
    realpath(buf, path);
    return 0;
}

int _convert_FILEPtr(FILE *stream, char *path){
    return _convert_fd(fileno(stream), path);
}

int _convert_char_buf(const void* ptr, char *result){
    snprintf(result, 32, "%s", (char*)ptr);
    for(int i=0; i<32; ++i){
        if(result[i] == '\0')
            break;
        if(!isprint(result[i]))
            result[i] = '.';
    }
    result[32] = '\0';
    return 0;
}


int chmod(const char *pathname, mode_t mode){
    static int (*_chmod)(const char *, mode_t);
    _chmod = _load_function(_chmod, "chmod");

    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _chmod(pathname, mode);
    fprintf(_stderr, "[logger] chmod(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group){
    static int (*_chown)(const char *, uid_t, gid_t);
    _chown = _load_function(_chown, "chown");
    
    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _chown(pathname, owner, group);
    fprintf(_stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", path, owner, group, ret);
    return ret;
}

int close(int fd){
    static int (*_close)(int);
    _close = _load_function(_close, "close");

    char path[PATH_MAX];
    _convert_fd(fd, path);

    int ret = _close(fd);
    fprintf(_stderr, "[logger] close(\"%s\") = %d\n", path, ret);
    return ret;
}

int creat(const char *pathname, mode_t mode){
    static int (*_creat)(const char *, mode_t);
    _creat = _load_function(_creat, "creat");

    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _creat(pathname, mode);
    fprintf(_stderr, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int creat64(const char *pathname, mode_t mode){
    static int (*_creat64)(const char *, mode_t);
    _creat64 = _load_function(_creat64, "creat64");

    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _creat64(pathname, mode);
    fprintf(_stderr, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int fclose(FILE *stream){
    static int (*_fclose)(FILE *);
    _fclose = _load_function(_fclose, "fclose");
    
    char path[PATH_MAX];
    _convert_FILEPtr(stream, path);
    
    int ret =  _fclose(stream); 
    fprintf(_stderr, "[logger] fclose(\"%s\") = %d\n", path, ret);
    return ret;    
}

FILE * fopen(const char *pathname, const char *mode){
    static FILE *(*_fopen)(const char *, const char *);
    _fopen = _load_function(_fopen, "fopen");
    

    FILE * ret = _fopen(pathname, mode);
    char path[PATH_MAX];
    realpath(pathname, path);
    fprintf(_stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
    
    return ret;
}

FILE * fopen64(const char *pathname, const char *mode){
    static FILE *(*_fopen64)(const char *, const char *);
    _fopen64 = _load_function(_fopen64, "fopen64");
    

    FILE * ret = _fopen64(pathname, mode);
    char path[PATH_MAX];
    realpath(pathname, path);
    fprintf(_stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
    
    return ret;
}

size_t fread(void *ptr, size_t size, size_t nmemb, FILE *stream){
    static size_t (*_fread)(void *ptr, size_t size, size_t nmemb, FILE *stream);
    _fread = _load_function(_fread, "fread");

    char char_buf[33];
    _convert_char_buf(ptr, char_buf);
    char path[PATH_MAX];
    _convert_FILEPtr(stream, path);

    size_t ret = _fread(ptr, size, nmemb, stream);
    fprintf(_stderr, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", char_buf, size, nmemb, path, ret);

    return ret;
}

size_t fwrite(const void *ptr, size_t size, size_t nmemb, FILE *stream){
    static size_t (*_fwrite)(const void *ptr, size_t size, size_t nmemb, FILE *stream);
    _fwrite = _load_function(_fwrite, "fwrite");

    char char_buf[33];
    _convert_char_buf(ptr, char_buf);
    char path[PATH_MAX];
    _convert_FILEPtr(stream, path);


    size_t ret = _fwrite(ptr, size, nmemb, stream);
    fprintf(_stderr, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", char_buf, size, nmemb, path, ret);

    return ret;
}

int open(const char *pathname, int flags, ...){
    static int (*_open)(const char *, int, mode_t);
    _open = _load_function(_open, "open");

    mode_t mode=0;
    
    if(flags & O_CREAT || flags & (__O_TMPFILE | O_DIRECTORY) ){
        va_list input_args;
        va_start (input_args, flags);
        mode = va_arg (input_args, mode_t);
        va_end(input_args);
    }

    int ret = _open(pathname, flags, mode);
    char path[PATH_MAX];
    realpath(pathname, path);
    fprintf(_stderr, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
    
    
    return ret;
}

int open64(const char *pathname, int flags, ...){
    static int (*_open64)(const char *, int, mode_t);
    _open64 = _load_function(_open64, "open64");

    mode_t mode = 0;
    if(flags & O_CREAT || flags & (__O_TMPFILE | O_DIRECTORY) ){
        va_list input_args;
        va_start (input_args, flags);
        mode = va_arg (input_args, mode_t);
        va_end(input_args);
    }

    int ret = _open64(pathname, flags, mode);
    char path[PATH_MAX];
    realpath(pathname, path);
    fprintf(_stderr, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
    return ret;
}


ssize_t read(int fd, void *buf, size_t count){
    static ssize_t (*_read)(int fd, void *buf, size_t count);
    _read = _load_function(_read, "read");

    char path[PATH_MAX];
    _convert_fd(fd, path);
    char char_buf[33];
    _convert_char_buf(buf, char_buf);

    ssize_t ret = _read(fd, buf, count);
    fprintf(_stderr, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", path, char_buf, count, ret);
    return ret;
}

int remove(const char *pathname){
    static int (*_remove)(const char *);
    _remove = _load_function(_remove, "remove");

    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _remove(pathname);
    fprintf(_stderr, "[logger] remove(\"%s\") = %d\n", path, ret);
    return ret;
}
      
int rename(const char *oldpath, const char *newpath){
    static int (*_rename)(const char*, const char *);
    _rename = _load_function(_rename, "rename");

    char old[PATH_MAX], new[PATH_MAX];
    realpath(oldpath, old);

    int ret = _rename(oldpath, newpath);
    realpath(newpath, new);
    fprintf(_stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", old, new, ret);
    return ret;
}

FILE *tmpfile(){
    static FILE* (*_tmpfile)();
    _tmpfile = _load_function(_tmpfile, "tmpfile");

    FILE *ret = _tmpfile();
    fprintf(_stderr, "[logger] tmpfile() = %p\n", ret);
    return ret;
}

FILE *tmpfile64(){
    static FILE* (*_tmpfile64)();
    _tmpfile64 = _load_function(_tmpfile64, "tmpfile64");

    FILE *ret = _tmpfile64();
    fprintf(_stderr, "[logger] tmpfile() = %p\n", ret);
    return ret;
}

ssize_t write(int fd, const void *buf, size_t count){
    static ssize_t (*_write)(int , const void *, size_t);
    _write = _load_function(_write, "write");

    char path[PATH_MAX];
    _convert_fd(fd, path);
    char char_buf[33];
    _convert_char_buf(buf, char_buf);

    ssize_t ret = _write(fd, buf, count);
    fprintf(_stderr, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", path, char_buf, count, ret);
    return ret;
}



