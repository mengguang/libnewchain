//
// Created by mengguang on 2020/2/24.
//

#include "portable_utils.h"

#include "misc.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

bool check_and_create_wallet_dir(const char *dir) {
    struct stat info;
    if (stat(dir, &info) != 0) {
        log_debug("can not access %s\n", dir);
#ifdef _WIN32
#include <direct.h>
        if (mkdir(dir) == 0) {
            log_debug("can not create dir: %s\n", dir);
            return true;
        } else {
            return false;
        }
#else
        if (mkdir(dir, 0700) != 0) {
            log_debug("can not create dir: %s\n", dir);
            return false;
        } else {
            return true;
        }
#endif
    } else if (info.st_mode & S_IFDIR) {
        return true;
    } else {
        log_error("%s exists and is not a dir.\n", dir);
        return false;
    }
}


#ifdef WIN32

#include <windows.h>

#else

#include <termios.h>
#include <unistd.h>

#endif

void SetStdinEcho(bool enable) {
#ifdef WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;
    GetConsoleMode(hStdin, &mode);

    if (!enable)
        mode &= ~ENABLE_ECHO_INPUT;
    else
        mode |= ENABLE_ECHO_INPUT;

    SetConsoleMode(hStdin, mode);

#else
    struct termios tty;
    tcgetattr(STDIN_FILENO, &tty);
    if (!enable)
        tty.c_lflag &= ~ECHO;
    else
        tty.c_lflag |= ECHO;

    (void) tcsetattr(STDIN_FILENO, TCSANOW, &tty);
#endif
}

bool read_keystore_file(const char *keystore_file_path, char *keystore_text, size_t *keystore_length) {
    FILE *fp = fopen(keystore_file_path, "r");
    if (!fp) {
        perror("fopen:");
        return false;
    }
    size_t n_read = 0;
    size_t read_block = 1024;
    while (!feof(fp)) {
        size_t n = 0;
        if (*keystore_length < n_read + read_block) {
            read_block = *keystore_length - n_read;
        }
        n = fread(keystore_text + n_read, 1, read_block, fp);
        if (n == 0) {
            perror("fread:");
            fclose(fp);
            return false;
        }
        n_read += n;
    }
    fclose(fp);
    *keystore_length = n_read;
    return true;
}

bool write_keystore_file(const char *keystore_file_path, char *keystore_text, size_t keystore_length) {
    FILE *fp = fopen(keystore_file_path, "w");
    if (!fp) {
        perror("fopen:");
        return false;
    }
    size_t n_write = 0;
    size_t write_block = 1024;
    while (n_write < keystore_length) {
        size_t n = 0;
        if (keystore_length < n_write + write_block) {
            write_block = keystore_length - n_write;
        }
        n = fwrite(keystore_text + n_write, 1, write_block, fp);
        if (n == 0) {
            perror("fwrite:");
            fclose(fp);
            return false;
        }
        n_write += n;
    }
    fclose(fp);
    return true;
}
