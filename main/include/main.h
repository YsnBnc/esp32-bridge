#ifndef _MAIN_H_
#define _MAIN_H_

/* Espressif libraries */
#include "sdkconfig.h"
#include <nvs_flash.h>
#include <esp_log.h>

/* wolfSSL  */
#include <wolfssl/wolfcrypt/settings.h> /* includes wolfSSL user-settings.h */
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#ifndef WOLFSSL_ESPIDF
    #warning "Problem with wolfSSL user_settings."
    #warning "Check components/wolfssl/include"
#endif
#include <wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h>
#include <wolfssl/version.h>

/* wolfSSH  */
#include <wolfssh/ssh.h>
#include <wolfssh/log.h>

#endif
