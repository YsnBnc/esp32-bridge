#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#define WOLFSSH_TEST_SERVER
#define WOLFSSH_TEST_ECHOSERVER

#ifdef WOLFSSL_USER_SETTINGS
    #include <wolfssl/wolfcrypt/settings.h>
#else
    #include <wolfssl/options.h>
#endif

#include <wolfssl/wolfcrypt/hash.h>
#include <wolfssl/wolfcrypt/coding.h>
#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/asn.h>
#include <wolfssl/wolfcrypt/asn_public.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#include <wolfssh/ssh.h>
#include <wolfssh/internal.h>
#include <wolfssh/wolfsftp.h>
#include <wolfssh/agent.h>
#include <wolfssh/test.h>
#include <wolfssl/wolfcrypt/ecc.h>

#include "uartserver.h"

#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
    #include <pthread.h>
#endif

#if defined(WOLFSSH_SHELL) && defined(USE_WINDOWS_API)
#pragma message ("echoserver with shell on windows is not supported, use wolfSSHd instead")
#undef WOLFSSH_SHELL
#endif

#if defined(WOLFSSL_NUCLEUS) || defined(WOLFSSH_ZEPHYR)
    /* use buffers for keys with server */
    #define NO_FILESYSTEM
    #define WOLFSSH_NO_EXIT
#endif

#ifdef NO_FILESYSTEM
    #include <wolfssh/certs_test.h>
#endif

#ifdef WOLFSSH_SHELL
    #ifdef HAVE_PTY_H
        #include <pty.h>
    #endif
    #ifdef HAVE_UTIL_H
        #include <util.h>
    #endif
    #ifdef HAVE_TERMIOS_H
        #include <termios.h>
    #endif
#ifndef USE_WINDOWS_API
    #include <pwd.h>
#endif
    #include <signal.h>
#if defined(__QNX__) || defined(__QNXNTO__)
    #include <errno.h>
    #include <unix.h>

#elif defined(USE_WINDOWS_API)
    #include <errno.h>
#else
    #include <sys/errno.h>
#endif
#endif /* WOLFSSH_SHELL */

#ifdef WOLFSSH_AGENT
    #include <stddef.h>
    #include <sys/socket.h>
    #include <sys/un.h>
#endif /* WOLFSSH_AGENT */

#ifdef HAVE_SYS_SELECT_H
    #include <sys/select.h>
#endif

#ifndef USE_WINDOWS_API
    #include <errno.h>
    #define SOCKET_ERRNO errno
    #define SOCKET_ECONNRESET ECONNRESET
    #define SOCKET_ECONNABORTED ECONNABORTED
    #define SOCKET_EWOULDBLOCK EWOULDBLOCK
#else
    #include <WS2tcpip.h>
    #define SOCKET_ERRNO WSAGetLastError()
    #define SOCKET_ECONNRESET WSAECONNRESET
    #define SOCKET_ECONNABORTED WSAECONNABORTED
    #define SOCKET_EWOULDBLOCK WSAEWOULDBLOCK
#endif


#ifndef NO_WOLFSSH_SERVER

static const char echoserverBanner[] = "wolfSSH Example Echo Server\n";

static int quit = 0;
wolfSSL_Mutex doneLock;
#define MAX_PASSWD_RETRY 3
static int passwdRetry = MAX_PASSWD_RETRY;


#ifndef EXAMPLE_HIGHWATER_MARK
    #define EXAMPLE_HIGHWATER_MARK 0x3FFF8000 /* 1GB - 32kB */
#endif

#ifndef EXAMPLE_BUFFER_SZ
    #define EXAMPLE_BUFFER_SZ 4096
#endif

#ifndef EXAMPLE_KEYLOAD_BUFFER_SZ
    #define EXAMPLE_KEYLOAD_BUFFER_SZ 1200
#endif

typedef struct {
    WOLFSSH* ssh;
    WS_SOCKET_T fd;
    word32 id;
    int echo;
    char nonBlock;
    byte channelBuffer[EXAMPLE_BUFFER_SZ];
    char statsBuffer[EXAMPLE_BUFFER_SZ];
} thread_ctx_t;


static byte find_char(const byte* str, const byte* buf, word32 bufSz)
{
    const byte* cur;

    while (bufSz) {
        cur = str;
        while (*cur != '\0') {
            if (*cur == *buf)
                return *cur;
            cur++;
        }
        buf++;
        bufSz--;
    }

    return 0;
}


static int dump_stats(thread_ctx_t* ctx)
{
    word32 statsSz;
    word32 txCount, rxCount, seq, peerSeq;

    wolfSSH_GetStats(ctx->ssh, &txCount, &rxCount, &seq, &peerSeq);

    WSNPRINTF(ctx->statsBuffer, sizeof ctx->statsBuffer,
            "Statistics for Thread #%u:\r\n"
            "  txCount = %u\r\n  rxCount = %u\r\n"
            "  seq = %u\r\n  peerSeq = %u\r\n",
            ctx->id, txCount, rxCount, seq, peerSeq);
    statsSz = (word32)WSTRLEN(ctx->statsBuffer);

    fprintf(stderr, "%s", ctx->statsBuffer);
    return wolfSSH_stream_send(ctx->ssh, (byte*)ctx->statsBuffer, statsSz);
}


static int process_bytes(thread_ctx_t* threadCtx,const byte* buffer, word32 bufferSz)
{
    int stop = 0;
    byte c;
    const byte matches[] = { 0x03, 0x05, 0x06, 0x00 };

    c = find_char(matches, buffer, bufferSz);
    switch (c) {
        case 0x03:
            stop = 1;
            break;
        case 0x05:
            if (dump_stats(threadCtx) <= 0)
                stop = 1;
            break;
        case 0x06:
            if (wolfSSH_TriggerKeyExchange(threadCtx->ssh) != WS_SUCCESS)
                stop = 1;
            break;
    }
    return stop;
}

int ChildRunning = 0;

static int ssh_worker(thread_ctx_t* threadCtx)
{
    WOLFSSH* ssh;
    WS_SOCKET_T sshFd;
    int rc = 0;

    if (threadCtx == NULL)
        return 1;

    ssh = threadCtx->ssh;
    if (ssh == NULL)
        return WS_FATAL_ERROR;

    sshFd = wolfSSH_get_fd(ssh);

    {
        /* Parent process */
        word32 shellChannelId = 0;

        ChildRunning = 1;
        
        // Main loop to handle SSH events and I/O
        while (ChildRunning) {
            fd_set readFds; // Set of file descriptors to monitor for reading
            WS_SOCKET_T maxFd; // The highest-numbered file descriptor in the set
            int cnt_r; // Count of bytes read from the SSH channel
            int cnt_w; // Count of bytes written to the SSH channel

            FD_ZERO(&readFds); // Initialize the set of file descriptors to monitor for reading
            FD_SET(sshFd, &readFds); // Add the SSH file descriptor to the set of file descriptors to monitor for reading
            maxFd = sshFd; // Initialize the highest-numbered file descriptor in the set to the SSH file descriptor

            // Wait for an event on one of the file descriptors in the set
            rc = select((int)maxFd + 1, &readFds, NULL, NULL, NULL);
            if (rc == -1)
                break;
            
            // Check if the SSH file descriptor is ready for reading
            if (FD_ISSET(sshFd, &readFds)) {
                word32 lastChannel = 0;

                /* The following tries to read from the first channel inside
                   the stream. If the pending data in the socket is for
                   another channel, this will return an error with id
                   WS_CHAN_RXD. That means the agent has pending data in its
                   channel. The additional channel is only used with the
                   agent. */
                cnt_r = wolfSSH_worker(ssh, &lastChannel);
                if (cnt_r < 0) {
                    rc = wolfSSH_get_error(ssh);
                    if (rc == WS_CHAN_RXD) {
                        if (lastChannel == shellChannelId) {
                            cnt_r = wolfSSH_ChannelIdRead(ssh, shellChannelId,
                                    threadCtx->channelBuffer,
                                    sizeof threadCtx->channelBuffer);
                            if (cnt_r <= 0)
                                break;
                            cnt_w = wolfSSH_ChannelIdSend(ssh, shellChannelId,
                                    threadCtx->channelBuffer, cnt_r);
                            if (cnt_r > 0) {
                                int doStop = process_bytes(threadCtx,
                                        threadCtx->channelBuffer, cnt_r);
                                ChildRunning = !doStop;
                            }
                            #endif
                            if (cnt_w <= 0)
                                break;
                        }
                    }
                    else if (rc == WS_CHANNEL_CLOSED) {

                        continue;
                    }
                    else if (rc != WS_WANT_READ) {
                        
                        break;
                    }
                }
            }

        }
    }
    return 0;
}



static int NonBlockSSH_accept(WOLFSSH* ssh)
{
    int ret;
    int error;
    WS_SOCKET_T sockfd;
    int select_ret = 0;

    ret = wolfSSH_accept(ssh);
    error = wolfSSH_get_error(ssh);
    sockfd = (WS_SOCKET_T)wolfSSH_get_fd(ssh);

    while ((ret != WS_SUCCESS
                && ret != WS_SCP_COMPLETE && ret != WS_SFTP_COMPLETE)
            && (error == WS_WANT_READ || error == WS_WANT_WRITE)) {

        if (error == WS_WANT_READ)
            printf("... server would read block\n");
        else if (error == WS_WANT_WRITE)
            printf("... server would write block\n");

        select_ret = tcp_select(sockfd, 1);
        if (select_ret == WS_SELECT_RECV_READY  ||
            select_ret == WS_SELECT_ERROR_READY ||
            error      == WS_WANT_WRITE)
        {
            ret = wolfSSH_accept(ssh);
            error = wolfSSH_get_error(ssh);
        }
        else if (select_ret == WS_SELECT_TIMEOUT)
            error = WS_WANT_READ;
        else
            error = WS_FATAL_ERROR;
    }

    return ret;
}

// Worker thread for handling a single connection
static THREAD_RETURN WOLFSSH_THREAD server_worker(void* vArgs)
{
    // Worker thread for handling a single connection
    int ret = 0, error = 0;
    thread_ctx_t* threadCtx = (thread_ctx_t*)vArgs;

    passwdRetry = MAX_PASSWD_RETRY;

    // Accept the SSH connection
    if (!threadCtx->nonBlock)
        ret = wolfSSH_accept(threadCtx->ssh);
    else
        ret = NonBlockSSH_accept(threadCtx->ssh);

    // Handle the result of the accept operation
    switch (ret) {
        case WS_SCP_COMPLETE:
            printf("scp file transfer completed\n");
            ret = 0;
            break;

        case WS_SUCCESS:
            ret = ssh_worker(threadCtx); // Handle the SSH connection
            break;
    }

    // Handle fatal errors
    if (ret == WS_FATAL_ERROR) {
        const char* errorStr;
        error = wolfSSH_get_error(threadCtx->ssh); // Get the error code

        errorStr = wolfSSH_ErrorToName(error); // Get the error name

        // Handle version mismatch errors
        if (error == WS_VERSION_E) {
            ret = 0; /* don't break out of loop with version miss match */
            printf("%s\n", errorStr);
        }
        // Handle user authentication errors
        else if (error == WS_USER_AUTH_E) {
            wolfSSH_SendDisconnect(threadCtx->ssh,
                    WOLFSSH_DISCONNECT_NO_MORE_AUTH_METHODS_AVAILABLE);
            ret = 0; /* don't break out of loop with user auth error */
            printf("%s\n", errorStr);
        }
        // Handle socket errors
        else if (error == WS_SOCKET_ERROR_E) {
            ret = 0;
            printf("%s\n", errorStr);
        }
    }
    
    // Gracefully shut down the SSH connection if there were no fatal errors
    if (error != WS_SOCKET_ERROR_E && error != WS_FATAL_ERROR) {
        ret = wolfSSH_shutdown(threadCtx->ssh); // Attempt to shut down the SSH connection

        /* peer hung up, stop shutdown */
        if (ret == WS_SOCKET_ERROR_E) {
            ret = 0;
        }

        error = wolfSSH_get_error(threadCtx->ssh); // Get the error code after shutdown attempt
        if (error != WS_SOCKET_ERROR_E &&
                (error == WS_WANT_READ || error == WS_WANT_WRITE)) {
            int maxAttempt = 10; /* make 10 attempts max before giving up */
            int attempt;

            for (attempt = 0; attempt < maxAttempt; attempt++) {
                ret = wolfSSH_worker(threadCtx->ssh, NULL);
                error = wolfSSH_get_error(threadCtx->ssh);

                /* peer succesfully closed down gracefully */
                if (ret == WS_CHANNEL_CLOSED) {
                    ret = 0;
                    break;
                }

                /* peer hung up, stop shutdown */
                if (ret == WS_SOCKET_ERROR_E) {
                    ret = 0;
                    break;
                }

                if (error == WS_WANT_READ || error == WS_WANT_WRITE) {
                    /* Wanting read or wanting write. Clear ret. */
                    ret = 0;
                }
                else {
                    break;
                }
            }

            if (attempt == maxAttempt) {
                printf("Gave up on gracefull shutdown, closing the socket\n");
            }
        }
    }

    // Clean up resources
    if (threadCtx->fd != -1) {
        WCLOSESOCKET(threadCtx->fd);
        threadCtx->fd = -1;
    }
    wolfSSH_free(threadCtx->ssh);

    // Log any errors that occurred during connection handling
    if (ret != 0) {
        fprintf(stderr, "Error [%d] \"%s\" with handling connection.\n", ret,
                wolfSSH_ErrorToName(error));
    #ifndef WOLFSSH_NO_EXIT
        wc_LockMutex(&doneLock);
        quit = 1;
        wc_UnLockMutex(&doneLock);
    #endif
    }

    WFREE(threadCtx, NULL, 0); // Free the thread context memory

    WOLFSSL_RETURN_FROM_THREAD(0); // Return from the thread
}

#define ECC_PATH "./keys/server-key-ecc.der"


/* returns buffer size on success */
static int load_key(byte isEcc, byte* buf, word32 bufSz)
{
    word32 sz = 0;

    /* using buffers instead */
    if (isEcc) {
        if ((word32)sizeof_ecc_key_der_256 > bufSz) {
            return 0;
        }
        WMEMCPY(buf, ecc_key_der_256, sizeof_ecc_key_der_256);
        sz = sizeof_ecc_key_der_256;
    }
    else {
        if ((word32)sizeof_rsa_key_der_2048 > bufSz) {
            return 0;
        }
        WMEMCPY(buf, (byte*)rsa_key_der_2048, sizeof_rsa_key_der_2048);
        sz = sizeof_rsa_key_der_2048;
    }
    return sz;
}


typedef struct StrList {
    const char* str;
    struct StrList* next;
} StrList;


static StrList* StrListAdd(StrList* list, const char* str)
{
    if (str != NULL) {
        StrList* newStr = (StrList*)WMALLOC(sizeof *newStr, NULL, 0);

        if (newStr != NULL) {
            newStr->str = str;
            newStr->next = list;
            list = newStr;
        }
    }

    return list;
}

static void StrListFree(StrList* list)
{
    StrList* curStr;

    while (list != NULL) {
        curStr = list;
        list = list->next;
        WFREE(curStr, NULL, 0);
    }
}


/* Map user names to passwords */
/* Use arrays for username and p. The password or public key can
 * be hashed and the hash stored here. Then I won't need the type. */
typedef struct PwMap {
    byte type;
    byte username[32];
    word32 usernameSz;
    byte p[WC_SHA256_DIGEST_SIZE];
    struct PwMap* next;
} PwMap;


typedef struct PwMapList {
    PwMap* head;
} PwMapList;


static PwMap* PwMapNew(PwMapList* list, byte type, const byte* username,
                       word32 usernameSz, const byte* p, word32 pSz)
{
    PwMap* map;

    map = (PwMap*)WMALLOC(sizeof(PwMap), NULL, 0);
    if (map != NULL) {
        map->type = type;
        if (usernameSz >= sizeof(map->username))
            usernameSz = sizeof(map->username) - 1;
        WMEMCPY(map->username, username, usernameSz + 1);
        map->username[usernameSz] = 0;
        map->usernameSz = usernameSz;

        if (type != WOLFSSH_USERAUTH_NONE) {
            wc_Sha256Hash(p, pSz, map->p);
        }

        map->next = list->head;
        list->head = map;
    }

    return map;
}


static void PwMapListDelete(PwMapList* list)
{
    if (list != NULL) {
        PwMap* head = list->head;

        while (head != NULL) {
            PwMap* cur = head;
            head = head->next;
            WMEMSET(cur, 0, sizeof(PwMap));
            WFREE(cur, NULL, 0);
        }
    }
}


static const char samplePasswordBuffer[] =
    "jill:upthehill\n"
    "jack:toor\n";


#ifndef WOLFSSH_NO_ECDSA_SHA2_NISTP256
static const char samplePublicKeyEccBuffer[] =
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBNkI5JTP6D0lF42tbxX19cE87hztUS6FSDoGvPfiU0CgeNSbI+aFdKIzTP5CQEJSvm25"
    "qUzgDtH7oyaQROUnNvk= hansel\n"
    "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAA"
    "BBBKAtH8cqaDbtJFjtviLobHBmjCtG56DMkP6A4M2H9zX2/YCg1h9bYS7WHd9UQDwXO1Hh"
    "IZzRYecXh7SG9P4GhRY= gretel\n";
#endif

static int LoadPasswordBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    char* username;
    char* password;

    /* Each line of passwd.txt is in the format
     *     username:password\n
     * This function modifies the passed-in buffer. */

    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (*str != 0) {
        delimiter = WSTRCHR(str, ':');
        if (delimiter == NULL) {
            return -1;
        }
        username = str;
        *delimiter = 0;
        password = delimiter + 1;
        str = WSTRCHR(password, '\n');
        if (str == NULL) {
            return -1;
        }
        *str = 0;
        str++;
        if (PwMapNew(list, WOLFSSH_USERAUTH_PASSWORD,
                     (byte*)username, (word32)WSTRLEN(username),
                     (byte*)password, (word32)WSTRLEN(password)) == NULL ) {

            return -1;
        }
    }

    return 0;
}


static int LoadPublicKeyBuffer(byte* buf, word32 bufSz, PwMapList* list)
{
    char* str = (char*)buf;
    char* delimiter;
    char* end = (char*)buf + bufSz;
    byte* publicKey64;
    word32 publicKey64Sz;
    byte* username;
    word32 usernameSz;
    byte*  publicKey;
    word32 publicKeySz;

    /* Each line of passwd.txt is in the format
     *     ssh-rsa AAAB3BASE64ENCODEDPUBLICKEYBLOB username\n
     * This function modifies the passed-in buffer. */
    if (list == NULL)
        return -1;

    if (buf == NULL || bufSz == 0)
        return 0;

    while (str < end && *str != 0) {
        /* Skip the public key type. This example will always be ssh-rsa. */
        delimiter = WSTRCHR(str, ' ');
        if (delimiter == NULL) {
            return -1;
        }
        if (str >= end)
            break;
        str = delimiter + 1;
        delimiter = WSTRCHR(str, ' ');
        if (delimiter == NULL) {
            return -1;
        }
        publicKey64 = (byte*)str;
        *delimiter = 0;
        publicKey64Sz = (word32)(delimiter - str);
        if (str >= end)
            break;
        str = delimiter + 1;
        delimiter = WSTRCHR(str, '\n');
        if (delimiter == NULL) {
            return -1;
        }
        username = (byte*)str;
        *delimiter = 0;
        usernameSz = (word32)(delimiter - str);
        str = delimiter + 1;

        /* more than enough space for base64 decode
         * not using WMALLOC because internal.h is not included for DYNTYPE_* */
        publicKey = (byte*)WMALLOC(publicKey64Sz, NULL, 0);
        if (publicKey == NULL) {
            fprintf(stderr, "error with WMALLOC\n");
            return -1;
        }
        publicKeySz = publicKey64Sz;

        if (Base64_Decode(publicKey64, publicKey64Sz,
                          publicKey, &publicKeySz) != 0) {

            WFREE(publicKey, NULL, 0);
            return -1;
        }

        if (PwMapNew(list, WOLFSSH_USERAUTH_PUBLICKEY,
                     username, usernameSz,
                     publicKey, publicKeySz) == NULL ) {

            WFREE(publicKey, NULL, 0);
            return -1;
        }
        WFREE(publicKey, NULL, 0);
    }

    return 0;
}


static int LoadPasswdList(StrList* strList, PwMapList* mapList)
{
    char names[256];
    char* passwd;
    int count = 0;

    while (strList) {
        WSTRNCPY(names, strList->str, sizeof names - 1);
        passwd = WSTRCHR(names, ':');
        if (passwd != NULL) {
            *passwd = 0;
            passwd++;

            PwMapNew(mapList, WOLFSSH_USERAUTH_PASSWORD,
                    (byte*)names, (word32)WSTRLEN(names),
                    (byte*)passwd, (word32)WSTRLEN(passwd));
        }
        else {
            fprintf(stderr, "Ignoring password: %s\n", names);
        }

        strList = strList->next;
        count++;
    }

    return count;
}

static int wsUserAuthResult(byte res,
                      WS_UserAuthData* authData,
                      void* ctx)
{
    printf("In auth result callback, auth = %s\n",
        (res == WOLFSSH_USERAUTH_SUCCESS) ? "Success" : "Failure");
    (void)authData;
    (void)ctx;
    return WS_SUCCESS;
}

// This is a simple user authentication callback that checks the username and password or public key against a list of valid users. 
// It returns WOLFSSH_USERAUTH_SUCCESS if the authentication is successful.
static int wsUserAuth(byte authType,WS_UserAuthData* authData,void* ctx)
{   
    // This is a simple user authentication callback that checks the username and password or public key against a list of valid users.
    PwMapList* list;
    PwMap* map;
    byte authHash[WC_SHA256_DIGEST_SIZE];

    if (ctx == NULL) {
        fprintf(stderr, "wsUserAuth: ctx not set");
        return WOLFSSH_USERAUTH_FAILURE;
    }

    // Check if the authentication type is valid. If not, return failure.
    if (authType != WOLFSSH_USERAUTH_PASSWORD &&
#ifdef WOLFSSH_ALLOW_USERAUTH_NONE
        authType != WOLFSSH_USERAUTH_NONE &&
#endif
        authType != WOLFSSH_USERAUTH_PUBLICKEY) {

        return WOLFSSH_USERAUTH_FAILURE;
    }

    // Hash the password or public key using SHA-256 and store it in authHash.
    if (authType == WOLFSSH_USERAUTH_PASSWORD) {
        wc_Sha256Hash(authData->sf.password.password,authData->sf.password.passwordSz,authHash); 
    }
    // If the authentication type is public key, hash the public key and store it in authHash.
    else if (authType == WOLFSSH_USERAUTH_PUBLICKEY) {
        wc_Sha256Hash(authData->sf.publicKey.publicKey,authData->sf.publicKey.publicKeySz,authHash);
    }

    // Check the username and authentication type against the list of valid users. 
    // If a match is found, compare the hashed password or public key with the stored hash. 
    // Return the appropriate authentication result.
    list = (PwMapList*)ctx;
    map = list->head;

    // Loop through the list of valid users and check for a match with the provided username and authentication type.
    while (map != NULL) {
        // Check if the username and authentication type match the current entry in the list.
        if (authData->usernameSz == map->usernameSz &&
            // Compare the provided username with the stored username. 
            // If they match, check the authentication type.
            WMEMCMP(authData->username, map->username, map->usernameSz) == 0 &&
            authData->type == map->type) {

            // If the authentication type is public key, compare the hashed public key with the stored hash.    
            if (authData->type == WOLFSSH_USERAUTH_PUBLICKEY) {
                // If the hashes match, return success. Otherwise, return invalid public key.
                if (WMEMCMP(map->p, authHash, WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                   return WOLFSSH_USERAUTH_INVALID_PUBLICKEY;
                }
            }
            // If the authentication type is password, compare the hashed password with the stored hash.
            else if (authData->type == WOLFSSH_USERAUTH_PASSWORD) {
                // If the hashes match, return success. 
                //Otherwise, decrement the password retry count and return invalid password or rejected based on the remaining retries.
                if (WMEMCMP(map->p, authHash, WC_SHA256_DIGEST_SIZE) == 0) {
                    return WOLFSSH_USERAUTH_SUCCESS;
                }
                else {
                    passwdRetry--;
                    return (passwdRetry > 0) ?
                        WOLFSSH_USERAUTH_INVALID_PASSWORD :
                        WOLFSSH_USERAUTH_REJECTED;
                 }
            }
            // If the authentication type is none, return success.
            #ifdef WOLFSSH_ALLOW_USERAUTH_NONE
            else if (authData->type == WOLFSSH_USERAUTH_NONE) {
                return WOLFSSH_USERAUTH_SUCCESS;
            }
            #endif /* WOLFSSH_ALLOW_USERAUTH_NONE */
            else {
                 return WOLFSSH_USERAUTH_INVALID_AUTHTYPE;
            }
        }
        // Move to the next entry in the list of valid users.
        map = map->next;
    }

    // If no match is found in the list, return invalid user.
    return WOLFSSH_USERAUTH_INVALID_USER;
}

static void ShowUsage(void)
{
    printf("echoserver %s\n", LIBWOLFSSH_VERSION_STRING);
    printf(" -?            display this help and exit\n");
    printf(" -1            exit after single (one) connection\n");
    printf(" -e            expect ECC public key from client\n");
    printf(" -E            load ECC private key first\n");
#ifdef WOLFSSH_SHELL
    printf(" -f            echo input\n");
#endif
    printf(" -p <num>      port to connect on, default %d\n", wolfSshPort);
    printf(" -N            use non-blocking sockets\n");
#ifdef WOLFSSH_SFTP
    printf(" -d <string>   set the home directory for SFTP connections\n");
#endif
    printf(" -j <file>     load in a SSH public key to accept from peer\n"
           "               (user assumed in comment)\n");
    printf(" -I <name>:<file>\n"
           "               load in a SSH public key to accept from peer\n");
    printf(" -J <name>:<file>\n"
           "               load in an X.509 PEM cert to accept from peer\n");
    printf(" -K <name>:<file>\n"
           "               load in an X.509 DER cert to accept from peer\n");
    printf(" -P <name>:<password>\n"
           "               add password to accept from peer\n");
}


static INLINE void SignalTcpReady(func_args* serverArgs, word16 port)
{
    (void)serverArgs;
    (void)port;
}

#define ES_ERROR(...) do { \
    fprintf(stderr, __VA_ARGS__); \
    serverArgs->return_code = EXIT_FAILURE; \
    WOLFSSL_RETURN_FROM_THREAD(0); \
} while(0)

THREAD_RETURN WOLFSSH_THREAD echoserver_test(void* args)
{
    func_args* serverArgs = (func_args*)args;
    WOLFSSH_CTX* ctx = NULL;
    PwMapList pwMapList;
    StrList* passwdList = NULL;
    WS_SOCKET_T listenFd = WOLFSSH_SOCKET_INVALID;
    word32 defaultHighwater = EXAMPLE_HIGHWATER_MARK;
    word32 threadCount = 0;
    int multipleConnections = 1;
    int userEcc = 0;
    int peerEcc = 0;
    int echo = 0;
    int ch;
    word16 port = wolfSshPort;
    char* readyFile = NULL;
    const char* defaultSftpPath = NULL;
    char  nonBlock  = 0;

    int     argc = serverArgs->argc;
    char**  argv = serverArgs->argv;
    serverArgs->return_code = EXIT_SUCCESS;

    if (argc > 0) {
        const char* optlist = "?1a:d:efEp:R:Ni:j:I:J:K:P:";
        myoptind = 0;
        while ((ch = mygetopt(argc, argv, optlist)) != -1) {
            switch (ch) {
                case '?' :
                    ShowUsage();
                    serverArgs->return_code = MY_EX_USAGE;
                    WOLFSSL_RETURN_FROM_THREAD(0);

                case '1':
                    multipleConnections = 0;
                    break;

                case 'a':
                    #ifdef WOLFSSH_CERTS
                        caCert = myoptarg;
                    #endif
                    break;
                case 'e' :
                    userEcc = 1;
                    break;

                case 'E':
                    peerEcc = 1;
                    break;

                case 'f':
                    #ifdef WOLFSSH_SHELL
                        echo = 1;
                    #endif
                    break;

                case 'p':
                    if (myoptarg == NULL) {
                        ES_ERROR("NULL port value");
                    }
                    else {
                        port = (word16)atoi(myoptarg);
                        #if !defined(NO_MAIN_DRIVER) || defined(USE_WINDOWS_API)
                            if (port == 0) {
                                ES_ERROR("port number cannot be 0");
                            }
                        #endif
                    }
                    break;

                case 'R':
                    readyFile = myoptarg;
                    break;

                case 'N':
                    nonBlock = 1;
                    break;

                case 'd':
                    defaultSftpPath = myoptarg;
                    break;

                case 'P':
                    passwdList = StrListAdd(passwdList, myoptarg);
                    break;

                default:
                    ShowUsage();
                    serverArgs->return_code = MY_EX_USAGE;
                    WOLFSSL_RETURN_FROM_THREAD(0);
            }
        }
    }
    myoptind = 0;      /* reset for test cases */
    wc_InitMutex(&doneLock);

#ifdef WOLFSSH_NO_RSA
    /* If wolfCrypt isn't built with RSA, force ECC on. */
    userEcc = 1;
    peerEcc = 1;
#endif
    (void)userEcc;

    if (wolfSSH_Init() != WS_SUCCESS) {
        //Libary initialization failed
        ES_ERROR("Couldn't initialize wolfSSH.\n");
    }

    //ctx is the context for the server, it holds keys and other information
    ctx = wolfSSH_CTX_new(WOLFSSH_ENDPOINT_SERVER, NULL); //initialize the server context
    if (ctx == NULL) {
        ES_ERROR("Couldn't allocate SSH CTX data.\n");
    }

    //initialize the password map list
    WMEMSET(&pwMapList, 0, sizeof(pwMapList));

    if (serverArgs->user_auth == NULL)
        //server arguments user_auth is NULL, so set the user authentication callback to wsUserAuth
        wolfSSH_SetUserAuth(ctx, wsUserAuth);
    else
        //otherwise, set the user authentication callback to the user_auth function provided in the server arguments
        wolfSSH_SetUserAuth(ctx, ((func_args*)args)->user_auth);
    
    //set the user authentication result callback to wsUserAuthResult
    wolfSSH_SetUserAuthResult(ctx, wsUserAuthResult);
    //set the banner for the server context to echoserverBanner
    wolfSSH_CTX_SetBanner(ctx, echoserverBanner);

    if (passwdList) {
        LoadPasswdList(passwdList, &pwMapList);
        StrListFree(passwdList);
        passwdList = NULL;
    }

    {
        const char* bufName = NULL;
    #ifndef WOLFSSH_SMALL_STACK
        byte buf[EXAMPLE_KEYLOAD_BUFFER_SZ];
    #endif
        byte* keyLoadBuf;
        word32 bufSz;

        keyLoadBuf = buf;
        bufSz = EXAMPLE_KEYLOAD_BUFFER_SZ;

        bufSz = load_key(peerEcc, keyLoadBuf, bufSz);
        if (bufSz == 0) {
            ES_ERROR("Couldn't load first key file.\n");
        }
        if (wolfSSH_CTX_UsePrivateKey_buffer(ctx, keyLoadBuf, bufSz,
                                             WOLFSSH_FORMAT_ASN1) < 0) {
            ES_ERROR("Couldn't use first key buffer.\n");
        }
        bufSz = (word32)WSTRLEN(samplePasswordBuffer);
        WMEMCPY(keyLoadBuf, samplePasswordBuffer, bufSz);
        keyLoadBuf[bufSz] = 0;
        LoadPasswordBuffer(keyLoadBuf, bufSz, &pwMapList);

        if (userEcc) {
        #ifndef WOLFSSH_NO_ECC
            bufName = samplePublicKeyEccBuffer;
        #endif
        }
        if (bufName != NULL) {
            bufSz = (word32)WSTRLEN(bufName);
            WMEMCPY(keyLoadBuf, bufName, bufSz);
            keyLoadBuf[bufSz] = 0;
            LoadPublicKeyBuffer(keyLoadBuf, bufSz, &pwMapList);
        }
    }

    /* if creating a ready file with port then override port to be 0 */
    if (readyFile != NULL) {
    #ifdef NO_FILESYSTEM
        ES_ERROR("cannot create readyFile with no file system.\r\n");
    #endif
    }
    tcp_listen(&listenFd, &port, 1);

    do {
        WS_SOCKET_T      clientFd = WOLFSSH_SOCKET_INVALID;
    #ifdef WOLFSSL_NUCLEUS
        struct addr_struct clientAddr;
    #else
        SOCKADDR_IN_T clientAddr;
        socklen_t     clientAddrSz = sizeof(clientAddr);
    #endif
        //Initialize a new WOLFSSH object for the server
        WOLFSSH*      ssh;
        thread_ctx_t* threadCtx;

        //Allocate memory for the thread context data
        threadCtx = (thread_ctx_t*)WMALLOC(sizeof(thread_ctx_t),
                NULL, 0);
        if (threadCtx == NULL) {
            ES_ERROR("Couldn't allocate thread context data.\n");
        }
        WMEMSET(threadCtx, 0, sizeof *threadCtx);

        //Create a new WOLFSSH object using the server context
        ssh = wolfSSH_new(ctx);
        if (ssh == NULL) {
            WFREE(threadCtx, NULL, 0); //Free the thread context memory
            ES_ERROR("Couldn't allocate SSH data.\n"); //Free the WOLFSSH object memory
        }
        //Set the user authentication context for the WOLFSSH object to the password map list
        wolfSSH_SetUserAuthCtx(ssh, &pwMapList); 
        /* Use the session object for its own highwater callback ctx */
        if (defaultHighwater > 0) {
            //Highwater mark is a threshold for the amount of data that can be buffered before the application is notified. 
            wolfSSH_SetHighwaterCtx(ssh, (void*)ssh); //Set the highwater context for the WOLFSSH object to itself
            wolfSSH_SetHighwater(ssh, defaultHighwater); //Set the highwater mark for the WOLFSSH object to the default highwater value
        }

    #ifdef WOLFSSH_SFTP
        if (SetDefaultSftpPath(ssh, defaultSftpPath) != 0) {
            ES_ERROR("Couldn't store default sftp path.\n");
        }
    #endif

        //Signal that the TCP server is ready to accept connections
        SignalTcpReady(serverArgs, port);

    #ifdef WOLFSSL_NUCLEUS
        clientFd = NU_Accept(listenFd, &clientAddr, 0);
    #else
        //Accept a new client connection on the listening socket
        clientFd = accept(listenFd, (struct sockaddr*)&clientAddr,
                                                         &clientAddrSz);
    #endif
        if (clientFd == -1) {
            ES_ERROR("tcp accept failed");
        }

        if (nonBlock)
            tcp_set_nonblocking(&clientFd);//Set the client socket to non-blocking mode if specified

        wolfSSH_set_fd(ssh, (int)clientFd); //Set the file descriptor for the WOLFSSH object to the client socket file descriptor

//Set the thread context data for the WOLFSSH object to the thread context structure
#if defined(WOLFSSL_PTHREADS) && defined(WOLFSSL_TEST_GLOBAL_REQ)
        threadCtx->ctx = ctx;
#endif
        //Set the thread context data for the WOLFSSH object to the thread context structure
        threadCtx->ssh = ssh;
        threadCtx->fd = clientFd;
        threadCtx->id = threadCount++;
        threadCtx->nonBlock = nonBlock;
        threadCtx->echo = echo;

        //Call the server worker function to handle the client connection
        server_worker(threadCtx);

    } while (multipleConnections && !quit);

    //Clean up resources and free memory
    if (listenFd != WOLFSSH_SOCKET_INVALID) {
        WCLOSESOCKET(listenFd);
    }
    wc_FreeMutex(&doneLock); //Free the mutex used for synchronization
    PwMapListDelete(&pwMapList); //Delete the password map list
    wolfSSH_CTX_free(ctx); //Free the server context
    if (wolfSSH_Cleanup() != WS_SUCCESS) {
        ES_ERROR("Couldn't clean up wolfSSH.\n");
    }

    (void)defaultSftpPath;
    WOLFSSL_RETURN_FROM_THREAD(0);
}

void wolfSSL_Debugging_ON(void);

int wolfSSH_Echoserver(int argc, char** argv)
{
    func_args args;

    WMEMSET(&args, 0, sizeof(args));
    args.argc = argc;
    args.argv = argv;

    WSTARTTCP();


#if !defined(WOLFSSL_NUCLEUS) && !defined(INTEGRITY) && !defined(__INTEGRITY)
    ChangeToWolfSshRoot();
#endif
    echoserver_test(&args);
    wolfSSH_Cleanup();
    return args.return_code;
}


#ifndef NO_MAIN_DRIVER

    int main(int argc, char** argv)
    {
        return wolfSSH_Echoserver(argc, argv);
    }

    int myoptind = 0;
    char* myoptarg = NULL;

#endif /* NO_MAIN_DRIVER */

