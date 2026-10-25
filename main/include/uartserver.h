#ifndef _ESP32_BRIDGE_UARTSERVER_H_
#define _ESP32_BRIDGE_UARTSERVER_H_

#include <types.h>

#ifndef WOLFSSH_THREAD
    #define WOLFSSH_THREAD WOLFSSL_THREAD
#endif

THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args);
int wolfSSH_Echoserver(int argc, char** argv);


#endif /* _ESP32_BRIDGE_UARTSERVER_H_ */
