#ifndef UPLOAD_H
#define UPLOAD_H

#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <libwebsockets.h>
#include "common_lib.h"
#include "cJSON.h"
#include "md5.h"

#define UPLOAD_FILENAME_MAXLEN	256
#define PNR_MAX_SENDFILE_NUM	100	/* 最大同时发送文件数 */

/*
 * Unlike ws, http is a stateless protocol.  This pss only exists for the
 * duration of a single http transaction.  With http/1.1 keep-alive and http/2,
 * that is unrelated to (shorter than) the lifetime of the network connection.
 */
struct pss {
	struct lws_spa *spa;		/* lws helper decodes multipart form */
	char filename[128];		/* the filename of the uploaded file */
	unsigned long long file_length; /* the amount of bytes uploaded */
	int fd;				/* fd on file being saved */
};

enum {
	FILE_UPLOAD_INIT = 0,
	FILE_UPLOAD_BEGIN = 1,
	FILE_UPLOAD_RUNNING = 2,
	FILE_UPLOAD_END = 3
};

struct im_sendfile_struct
{
	int log_id;
	int msgtype;
	int filesize;	/* 文件总大小 */
	int rcvlen;	/* 已接收文件大小 */
	int fd;		/* 写入文件描述符 */
	int status;	/* 文件写入状态 */
    int filetype;
	char fromuser_toxid[TOX_ID_STR_LEN+1];
    char touser_toxid[TOX_ID_STR_LEN+1];
	char filename[UPLOAD_FILENAME_MAXLEN];
	char fullfilename[UPLOAD_FILENAME_MAXLEN];
    char srckey[PNR_RSA_KEY_MAXLEN+1];
    char dstkey[PNR_RSA_KEY_MAXLEN+1];
	char md5[33];
};

int callback_upload(struct lws *wsi, enum lws_callback_reasons reason, void *user, void *in, size_t len);

#endif

