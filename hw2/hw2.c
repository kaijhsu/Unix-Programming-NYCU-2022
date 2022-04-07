#include <stdio.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <limits.h>
#include <stdlib.h>
#include <unistd.h>
#include <ctype.h>

void* _load_function(void *fPtr, const char *name){
    if(fPtr != NULL)
        return fPtr;

    if(fPtr == NULL){
        void *handle = dlopen("libc.so.6", RTLD_LAZY);
        if(handle != NULL)
            return dlsym(handle, name);
    }
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
    fprintf(stderr, "[logger] chmod(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int chown(const char *pathname, uid_t owner, gid_t group){
    static int (*_chown)(const char *, uid_t, gid_t);
    _chown = _load_function(_chown, "chown");
    
    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _chown(pathname, owner, group);
    fprintf(stderr, "[logger] chown(\"%s\", %d, %d) = %d\n", path, owner, group, ret);
    return ret;
}

int close(int fd){
    static int (*_close)(int);
    _close = _load_function(_close, "close");

    char path[PATH_MAX];
    _convert_fd(fd, path);

    int ret = _close(fd);
    fprintf(stderr, "[logger] close(\"%s\") = %d\n", path, ret);
    return ret;
}

int creat(const char *pathname, mode_t mode){
    static int (*_creat)(const char *, mode_t);
    _creat = _load_function(_creat, "creat");

    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _creat(pathname, mode);
    fprintf(stderr, "[logger] creat(\"%s\", %o) = %d\n", path, mode, ret);
    return ret;
}

int fclose(FILE *stream){
    static int (*_fclose)(FILE *);
    _fclose = _load_function(_fclose, "fclose");
    
    char path[PATH_MAX];
    _convert_FILEPtr(stream, path);
    
    int ret =  _fclose(stream); 
    fprintf(stderr, "[logger] fclose(\"%s\") = %d\n", path, ret);
    return ret;    
}

FILE * fopen(const char *pathname, const char *mode){
    static FILE *(*_fopen)(const char *, const char *);
    _fopen = _load_function(_fopen, "fopen");
    
    char path[PATH_MAX];
    realpath(pathname, path);

    FILE * ret = _fopen(pathname, mode);
    fprintf(stderr, "[logger] fopen(\"%s\", \"%s\") = %p\n", path, mode, ret);
    
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
    fprintf(stderr, "[logger] fread(\"%s\", %ld, %ld, \"%s\") = %ld\n", char_buf, size, nmemb, path, ret);

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
    fprintf(stderr, "[logger] fwrite(\"%s\", %ld, %ld, \"%s\") = %ld\n", char_buf, size, nmemb, path, ret);

    return ret;
}

int open(const char *pathname, int flags, mode_t mode){
    static int (*_open)(const char *, int, mode_t);
    _open = _load_function(_open, "open");

    int ret = _open(pathname, flags, mode);
    char path[PATH_MAX];
    realpath(pathname, path);
    fprintf(stderr, "[logger] open(\"%s\", %o, %o) = %d\n", path, flags, mode, ret);
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
    fprintf(stderr, "[logger] read(\"%s\", \"%s\", %ld) = %ld\n", path, char_buf, count, ret);
    return ret;
}

int remove(const char *pathname){
    static int (*_remove)(const char *);
    _remove = _load_function(_remove, "remove");

    char path[PATH_MAX];
    realpath(pathname, path);

    int ret = _remove(pathname);
    fprintf(stderr, "[logger] remove(\"%s\") = %d\n", path, ret);
    return ret;
}
      
int rename(const char *oldpath, const char *newpath){
    static int (*_rename)(const char*, const char *);
    _rename = _load_function(_rename, "rename");

    char old[PATH_MAX], new[PATH_MAX];
    realpath(oldpath, old);
    realpath(newpath, new);

    int ret = _rename(oldpath, newpath);
    fprintf(stderr, "[logger] rename(\"%s\", \"%s\") = %d\n", old, new, ret);
    return ret;
}

FILE *tmpfile(){
    static FILE* (*_tmpfile)();
    _tmpfile = _load_function(_tmpfile, "tmpfile");

    FILE *ret = _tmpfile();
    fprintf(stderr, "[logger] tmpfile() = %p\n", ret);
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
    fprintf(stderr, "[logger] write(\"%s\", \"%s\", %ld) = %ld\n", path, char_buf, count, ret);
    return ret;
}



