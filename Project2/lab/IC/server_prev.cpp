#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <cstdlib>
#include <unistd.h>
#include <sys/stat.h>

using namespace std;

#define CONFIG_PATH "/shared/config.data"
#define DONE_PATH "/shared/exploit_done"

// vulnerable buffer
char user_input[64];

// logging
void log_message(const char *msg) {
    char buf[96];
    sprintf(buf, "[LOG]: %s", msg);
    cout << buf << endl;
}

void maintenance_task(const char *arg) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd), "echo '%s' >> /tmp/server.log", arg);
    system(cmd);
}

// parse config
void parse_config() {
    ifstream file(CONFIG_PATH);
    string line;

    while (getline(file, line)) {
        size_t pos = line.find('=');
        if (pos == string::npos) continue;

        string key = line.substr(0, pos);
        string value = line.substr(pos + 1);

        if (key == "user_input") {
            strcpy(user_input, value.c_str());
        }
    }
}

// main logic
void run_server() {
    cout << "[+] Running server..." << endl;
    log_message(user_input);
}

bool file_exists(const char *path) {
    return access(path, F_OK) == 0;
}

int main() {
    memset(user_input, 0, sizeof(user_input));
    strcpy(user_input, "hello");

    while (!file_exists(DONE_PATH)) {
        usleep(100 * 1000);
    }

    cout << "[+] Detected exploit_done, reading config..." << endl;
    if (unlink(DONE_PATH) == 0) {
        cout << "[+] exploit_done removed, ready for next round" << endl;
    } else 
         cerr << "[-] Failed to remove exploit_done" << endl;

    parse_config();
    run_server();


    return 0;
}

