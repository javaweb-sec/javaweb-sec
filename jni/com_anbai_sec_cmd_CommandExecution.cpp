//
// Created by yz on 2019/12/6.
//
#include <iostream>
#include <stdlib.h>
#include <cstring>
#include <string>
#include "com_anbai_sec_cmd_CommandExecution.h"

using namespace std;

JNIEXPORT jstring

JNICALL Java_com_anbai_sec_cmd_CommandExecution_exec
        (JNIEnv *env, jclass jclass, jstring str) {

    if (str != NULL) {
        jboolean jsCopy;
        const char *cmd = env->GetStringUTFChars(str, &jsCopy);
        FILE *fd  = popen(cmd, "r");

        if (fd != NULL) {
            string result;
            char buf[128];

            while (fgets(buf, sizeof(buf), fd) != NULL) {
                result +=buf;
            }

            pclose(fd);
            return env->NewStringUTF(result.c_str());
        }

    }

    return NULL;
}
