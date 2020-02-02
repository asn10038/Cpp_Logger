/* 
 * File:   Log.h
 * Author: Alberto Lepe <dev@alepe.com>
 *
 * Created on December 1, 2015, 6:00 PM
 */

#ifndef LOG_H
#define LOG_H

#include <iostream>

using namespace std;

enum typelog {
    DEBUG,
    INFO,
    WARN,
    ERROR
};

struct structlog {
    bool headers = false;
    typelog level = WARN;
};

extern structlog LOGCFG;

class LOG {
public:
    LOG() {}
    LOG(typelog type) {
        msglevel = type;
        if(LOGCFG.headers) {
            operator << ("["+getLabel(type)+"]");
        }
    }
    ~LOG() {
        if(opened) {
            cout << endl;
        }
        opened = false;
    }
    template<class T>
    LOG &operator<<(const T &msg) {
        if(msglevel >= LOGCFG.level) {
            cout << msg;
            opened = true;
        }
        return *this;
    }
private:
    bool opened = false;
    typelog msglevel = DEBUG;
    inline string getLabel(typelog type) {
        string label;
        switch(type) {
            case DEBUG: label = "DEBUG"; break;
            case INFO:  label = "INFO "; break;
            case WARN:  label = "WARN "; break;
            case ERROR: label = "ERROR"; break;
        }
        return label;
    }
};

#endif  /* LOG_H */
/* Usage example 
#include "Log.h"

int main(int argc, char** argv) {
    //Config: -----(optional)----
    structlog LOGCFG = {};
    LOGCFG.headers = false; 
    LOGCFG.level = DEBUG;
    //---------------------------
    LOG(INFO) << "Main executed with " << (argc - 1) << " arguments";
}
*/
