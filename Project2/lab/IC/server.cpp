#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>
#include <algorithm>

using namespace std;

#define CONFIG_PATH "/shared/config.data"
#define DONE_PATH "/shared/exploit_done"

char user_input[512];
size_t user_input_len = 0;

void maintenance_task(const char *arg) {
    system(arg);
}

__attribute__((used))
void execute_task() {
    maintenance_task(user_input);
    exit(0);
}

void log_message(const char *msg, size_t len) {
    char buf[96];
    memcpy(buf, msg, len); 
}

void parse_config() {
    ifstream file(CONFIG_PATH, ios::binary);
    string line;

    while (getline(file, line)) {
        size_t pos = line.find('=');
        if (pos == string::npos) continue;

        string key = line.substr(0, pos);
        string value = line.substr(pos + 1);

        if (key == "user_input") {
            user_input_len = value.size();
            memcpy(user_input, value.data(), user_input_len);
        }
    }
}

void run_server() {
    cout << "[+] Running server..." << endl;
    log_message(user_input, user_input_len);
}

bool file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

int main() {
    memset(user_input, 0, sizeof(user_input));
    strcpy(user_input, "hello");
    user_input_len = strlen(user_input);

    while (!file_exists(DONE_PATH)) {
        usleep(100 * 1000);
    }

    cout << "[+] Detected exploit_done, reading config..." << endl;

    if (unlink(DONE_PATH) == 0) {
        cout << "[+] exploit_done removed, ready for next round" << endl;
    } else {
        cerr << "[-] Failed to remove exploit_done" << endl;
    }

    parse_config();
    run_server();

    return 0;
}

