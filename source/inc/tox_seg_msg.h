#ifndef __TOX_SEG_MSG_H
#define __TOX_SEG_MSG_H

#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <semaphore.h> 
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/param.h>
#include <getopt.h>
#include <sys/socket.h>
#include <locale.h>
#include <errno.h> 
#include <pthread.h>
#include "pn_imserver.h"

#define MAX_SEND_DATA_SIZE	1100

struct tox_msg_send {
    struct list_head list;
    int msgid;
    int friendnum;
    int msglen;
    int offset;
    int recvtime;
    char *msg;
    char frame[256];
};

struct tox_textmsg_info
{
    int msgid;
    int friendnum;
    int msglen;
    int offset;
    char* pmsg;
};
extern struct list_head g_tox_msg_send_list;
extern pthread_rwlock_t g_tox_msg_send_lock;

void tox_seg_msg_process(Tox *m, int friendnum, struct imcmd_msghead_struct *msg_head);
void *tox_seg_msg_flush(void *para);

#endif

