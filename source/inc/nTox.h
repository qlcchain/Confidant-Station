/*
 * Textual frontend for Tox.
 */

/*
 * Copyright ? 2016-2017 The TokTok team.
 * Copyright ? 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifndef NTOX_H
#define NTOX_H

#include <ctype.h>
#include "tox.h"
#include "bootstrap.h"
#include "aes.h"
#include "base64.h"
#include "common_lib.h"
#include "upload.h"

#define STRING_LENGTH 512

typedef struct {
    uint8_t id[TOX_PUBLIC_KEY_SIZE];
    uint8_t accepted;
} Friend_request;

#define NUM_FILE_SENDERS 128
typedef struct {
    FILE *file;
    struct lws_cache_msg_struct *msg;
    uint32_t filenumber;
	uint32_t friendnum;
	uint32_t lastsndtime;
} File_Sender;
File_Sender file_senders[PNR_IMUSER_MAXNUM+1][NUM_FILE_SENDERS];

#define NUM_FILE_RCV 128
typedef struct {
    FILE *file;
    uint32_t friendnum;
    uint32_t filenumber;
	uint32_t lastrcvtime;
	char filename[UPLOAD_FILENAME_MAXLEN];
} File_Rcv;
File_Rcv file_rcv[PNR_IMUSER_MAXNUM+1][NUM_FILE_RCV];

int CreatedP2PNetwork(void);
int GetFriendNumInFriendlist_new(Tox *plinknode, char *friendId_P);
void set_timer(void);
void get_id(Tox *m, char *data);
int insert_tox_file_msgnode(int userid, char *from, char *to,
    char *pmsg, int msglen, char *filename, char *filepath, int type, 
    int logid, int msgid, int ftype,char* srckey,char* dstkey);
int get_friendid_bytoxid(int userid,char* friend_name);
int check_and_add_friends(Tox * plinknode,char * friendid_p,char* datafile);
int insert_tox_msgnode(int userid, char *from, char *to,
    char *pmsg, int msglen, int type, int logid, int msgid, char* srckey, char* dstkey);
int insert_tox_msgnode_v3(int userid, char *from, char *to,
    char *pmsg, int msglen, int type, int logid, int msgid,char* sign, char* nonce, char* prikey);
int tox_datafile_check(int user_index,char* datafile,int* new_flag);
int tox_datafile_backup(int user_index,char* datafile);
int imtox_send_file_to_app(Tox *tox, int friendnum, char *fromid, char *filepath,int msgid,int filefrom);
int get_index_by_toxhandle(Tox *ptox);
int add_friends_force(Tox *plinknode, char *friendid, char *msg);
int get_uindex_by_toxfriendnum(Tox *tox, uint32_t friendnumber,int* uindex);
int get_ppm_usernum_by_toxfriendnum(Tox *tox, uint32_t friendnumber,int user_id,int* ppm_friendid);
#endif
