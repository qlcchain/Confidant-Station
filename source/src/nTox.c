/*
 * Textual frontend for Tox.
 */

/*
 * Copyright 漏 2016-2017 The TokTok team.
 * Copyright 漏 2013 Tox project.
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
#include <pthread.h>  

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define _WIN32_WINNT 0x501
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif
#include <sys/select.h>
#include <sys/time.h>
#include "ccompat.h"
#include "misc_tools.h"
#include "nTox.h"
#include <locale.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>
#include "cJSON.h"
#include "common_lib.h"
#include "pn_imserver.h"
#include "upload.h"
#include "sql_db.h"
#include "pn_imserver.h"
#include "md5.h"

#if defined(_WIN32) || defined(__WIN32__) || defined (WIN32)
#define c_sleep(x) Sleep(x)
#else
#include <unistd.h>
#define c_sleep(x) usleep(1000*(x))
#endif

#define IP_MAX_SIZE 45
#define DEFAULT_P2PID_FILENAME     "p2pid.txt"
#define FRADDR_TOSTR_CHUNK_LEN 8
#define FRAPUKKEY_TOSTR_BUFSIZE (TOX_PUBLIC_KEY_SIZE * 2 + 1)
#define FRADDR_TOSTR_BUFSIZE (TOX_ADDRESS_SIZE * 2 + TOX_ADDRESS_SIZE / FRADDR_TOSTR_CHUNK_LEN + 1)

//added by willcao
#define immsgForward        "immsgForward"
#define immsgForwardRes     "immsgForwardRes"

enum MSG_TYPE
{
	TYPE_CheckConnectReq	= 0,
	TYPE_JoinGroupChatReq,
	TYPE_RecordSaveReq,
	//added by willcao
	TYPE_immsgForward,
	TYPE_immsgForwardRes,
	TYPE_UNKNOW = -1
};

const char *data_file_name = NULL;
char path[100] = {DAEMON_PNR_TOP_DIR};
Tox *qlinkNode = NULL;
char dataPathFile[200] = {0};
extern struct im_user_array_struct g_imusr_array;
extern int g_p2pnet_init_flag;//tox p2p网络初始化完成标识
extern struct im_user_struct g_daemon_tox;
extern struct im_user_array_struct g_imusr_array;
extern Tox* g_tox_linknode[PNR_IMUSER_MAXNUM+1];
extern struct imuser_toxmsg_struct g_tox_msglist[PNR_IMUSER_MAXNUM+1];
extern pthread_mutex_t tox_msglock[PNR_IMUSER_MAXNUM+1];
extern struct pnr_tox_datafile_struct g_tox_datafile[PNR_IMUSER_MAXNUM+1];
char  homeDirPath[100] = {DAEMON_PNR_TOP_DIR};

int im_nodelist_addfriend(int index,char* from_user,char* to_user,char* nickname,char* userkey);
int friend_Message_process(Tox* m, int friendnum, char *message);
int map_msg(char *type);
int get_index_by_toxhandle(Tox *ptox);
int writep2pidtofile(char *id);
int processImMsgForward (Tox *m, cJSON* pJson,int friendnum);
int processImMsgForwardRes(Tox *m, cJSON *pJson, int friendnum);
static int save_data(Tox *m);
static int save_data_new(Tox *m);
int insert_lws_msgnode(int id,char* puser,char* pmsg,int msg_len);
int im_tox_rcvmsg_deal(Tox *m, char *pmsg, int len, int friendnum);

static void tox_file_chunk_request(Tox *tox, uint32_t friend_number, 
    uint32_t file_number, uint64_t position, size_t length, void *user_data)
{
    unsigned int i;
	int *index = (int *)user_data;
	File_Sender *sender = &file_senders[*index][0];
    int msgid;
    int ret = 0;
    TOX_ERR_FILE_SEND_CHUNK err;
	char filepath[256] = {0};

    for (i = 0; i < NUM_FILE_SENDERS; ++i) {
        /* This is slow */
        if (sender[i].file && sender[i].friendnum == friend_number 
			&& sender[i].filenumber == file_number) {
			get_file_name(sender[i].file, filepath, sizeof(filepath));

			if (length == 0) {
                fclose(sender[i].file);
				
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "file(%s) transfer completed", filepath);

				if (sender[i].msg) {
	                pnr_msgcache_getid(sender[i].msg->userid, &msgid);
					insert_tox_msgnode(sender[i].msg->userid, sender[i].msg->fromid, 
						sender[i].msg->toid, sender[i].msg->msg, sender[i].msg->msglen, 
						PNR_IM_CMDTYPE_PUSHFILE_TOX, 0, msgid, sender[i].msg->srckey, sender[i].msg->dstkey);
					pnr_msgcache_dbdelete(sender[i].msg->msgid, sender[i].msg->userid);
				}
				
				memset(&sender[i], 0, sizeof(File_Sender));
				break;
            }

            fseek(sender[i].file, position, SEEK_SET);
            VLA(uint8_t, data, length);
            int len = fread(data, 1, length, sender[i].file);

            ret = tox_file_send_chunk(tox, friend_number, file_number, position, data, len, &err);
            if (ret == 0) {
				if (sender[i].msg) {
					sender[i].msg->filestatus = 0;
				}

				DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox send file(%s) err(%d)!", filepath, err);
            }

			sender[i].lastsndtime = time(NULL);

            break;
        }
    }
}

static void frpuk_to_str(uint8_t *id_bin, char *id_str)
{
    uint32_t i, delta = 0, pos_extra = 0, sum_extra = 0;

    for (i = 0; i < TOX_PUBLIC_KEY_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);

        if ((i + 1) == TOX_PUBLIC_KEY_SIZE) {
            pos_extra = 2 * (i + 1) + delta;
        }

        if (i >= TOX_PUBLIC_KEY_SIZE) {
            sum_extra |= id_bin[i];
        }

/*
        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
        */
    }

    id_str[2 * i + delta] = 0;

    if (!sum_extra) {
        id_str[pos_extra] = 0;
    }
}

static void fraddr_to_str(uint8_t *id_bin, char *id_str)
{
    uint32_t i, delta = 0, pos_extra = 0, sum_extra = 0;

    for (i = 0; i < TOX_ADDRESS_SIZE; i++) {
        sprintf(&id_str[2 * i + delta], "%02hhX", id_bin[i]);

        if ((i + 1) == TOX_PUBLIC_KEY_SIZE) {
            pos_extra = 2 * (i + 1) + delta;
        }

        if (i >= TOX_PUBLIC_KEY_SIZE) {
            sum_extra |= id_bin[i];
        }

/*
        if (!((i + 1) % FRADDR_TOSTR_CHUNK_LEN)) {
            id_str[2 * (i + 1) + delta] = ' ';
            delta++;
        }
        */
    }

    id_str[2 * i + delta] = 0;

    if (!sum_extra) {
        id_str[pos_extra] = 0;
    }
}

void get_id(Tox *m, char *data)
{
    uint8_t address[TOX_ADDRESS_SIZE];
    tox_self_get_address(m, address);
    fraddr_to_str(address, data);
}

static int getfriendname_terminated(Tox *m, int friendnum, char *namebuf)
{
    tox_friend_get_name(m, friendnum, (uint8_t *)namebuf, NULL);
    int res = tox_friend_get_name_size(m, friendnum, NULL);

    if (res >= 0) {
        namebuf[res] = 0;
    } else {
        namebuf[0] = 0;
    }

    return res;
}

int map_msg(char* type)
{
	if (!strcmp(immsgForward, type)) {
		return TYPE_immsgForward;
	} else if (!strcmp(immsgForwardRes, type)) {
        return TYPE_immsgForwardRes;
    } else {
		return TYPE_UNKNOW;
	}
}

int friend_Message_process(Tox *m, int friendnum, char *message)
{
	char type[32] = {0};

	if (!message)
		return -1;

	cJSON *pJson = cJSON_Parse(message);
	if (!pJson)																						  
		return -2;

	cJSON *pSub = cJSON_GetObjectItem(pJson, "type");
	if (!pSub)
		return -3;

	strcpy(type, pSub->valuestring);

    switch (map_msg(type)) {
    case TYPE_immsgForward:
		processImMsgForward(m, pJson, friendnum);
        break;
    case TYPE_immsgForwardRes:
        processImMsgForwardRes(m, pJson, friendnum);
        break;
	case TYPE_UNKNOW:
		DEBUG_PRINT(DEBUG_LEVEL_NORMAL, "UNKNOW Message(%s)", type);
		break;
	default:
		break;
    }
	
	cJSON_Delete(pJson);
	return 0;
}

static void print_formatted_message(Tox *m, char *message, int friendnum)
{
    char name[TOX_MAX_NAME_LENGTH + 1] = {0};
    
    getfriendname_terminated(m, friendnum, name);

    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"rec friend(%s) msg(%s)", name, message);
		
	friend_Message_process(m, friendnum, message);
}

/*****************************************************************************
 函 数 名  : auto_accept_request
 功能描述  : 自动添加好友
 输入参数  : Tox *m                     
             const uint8_t *public_key  
             const uint8_t *data        
             size_t length              
             void *userdata             
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月7日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void auto_accept_request(Tox *m, const uint8_t *public_key, 
    const uint8_t *data, size_t length, void *userdata)
{
	uint8_t fraddr_bin[TOX_ADDRESS_SIZE] = {0};
    char fraddr_str[FRADDR_TOSTR_BUFSIZE] = {0};
	Tox_Err_Friend_Add err;

	fraddr_to_str(public_key, fraddr_str);
		
	uint32_t num = tox_friend_add_norequest(m, public_key, &err);
	if (num == UINT32_MAX) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox add friend(%s) failed(%d)", fraddr_str, err);
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "friend(%s) request accepted as friendnum (%d)", fraddr_str, num);
        save_data_new(m);
	}
}

/*****************************************************************************
 函 数 名  : friend_request_cb
 功能描述  : 处理好友请求
 输入参数  : Tox *m                     
             const uint8_t *public_key  
             const uint8_t *data        
             size_t length              
             void *userdata             
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月7日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void friend_request_cb(Tox *m, const uint8_t *public_key, 
    const uint8_t *data, size_t length, void *userdata)
{
	int msgid = 0;
	char *pmsg = NULL;
	int *userindex = (int *)userdata;
    cJSON *item = NULL;
	char *itemstr = NULL;
	struct im_friend_msgstruct friend;

	DEBUG_PRINT(DEBUG_LEVEL_INFO, "recv friend msg:%s", data);
	
	cJSON *rootJson = cJSON_Parse((char *)data);
	if (!rootJson) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse json err(%s)", data);
		return;
	}

	cJSON *params = cJSON_GetObjectItem(rootJson, "params");
	if (!params) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get params err(%s)", data);
		return;
	}

	cJSON *action = cJSON_GetObjectItem(params, "Action");
	if (!action || !action->valuestring) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get action err(%s)", data);
		cJSON_Delete(rootJson);
		return;
	}

	pnr_msgcache_getid(*userindex, &msgid);
	cJSON_AddItemToObject(rootJson, "msgid", cJSON_CreateNumber(msgid));
	pmsg = cJSON_PrintUnformatted(rootJson);

	if (!strcmp(action->valuestring, PNR_IMCMD_ADDFRIENDREPLY)) {
		memset(&friend, 0, sizeof(friend));
		
		CJSON_GET_VARSTR_BYKEYWORD(params, item, itemstr, "UserId", friend.fromuser_toxid, TOX_ID_STR_LEN);
		CJSON_GET_VARSTR_BYKEYWORD(params, item, itemstr, "NickName", friend.nickname, PNR_USERNAME_MAXLEN);
        CJSON_GET_VARSTR_BYKEYWORD(params, item, itemstr, "FriendId", friend.touser_toxid, TOX_ID_STR_LEN);
        CJSON_GET_VARSTR_BYKEYWORD(params, item, itemstr, "FriendName", friend.friend_nickname, TOX_ID_STR_LEN);
        CJSON_GET_VARSTR_BYKEYWORD(params, item, itemstr, "UserKey", friend.user_pubkey, PNR_USER_PUBKEY_MAXLEN);
        CJSON_GET_VARINT_BYKEYWORD(params, item, itemstr, "Result", friend.result, 0);

        //这里需要反向一下
        if (friend.result == OK) {
            pnr_friend_dbinsert(friend.touser_toxid, friend.fromuser_toxid, friend.nickname, friend.user_pubkey);
            im_nodelist_addfriend(*userindex, friend.touser_toxid, friend.fromuser_toxid, friend.nickname, friend.user_pubkey);
        }

		pnr_msgcache_dbinsert(msgid, friend.fromuser_toxid, friend.touser_toxid,
            PNR_IM_CMDTYPE_ADDFRIENDREPLY, pmsg, strlen(pmsg), NULL, NULL, 0, 
            PNR_MSG_CACHE_TYPE_TOXA, 0, "", "");
	} else if (!strcmp(action->valuestring, PNR_IMCMD_ADDFRIENDPUSH)) {
		pnr_msgcache_dbinsert(msgid, "", g_imusr_array.usrnode[*userindex].user_toxid, 
			PNR_IM_CMDTYPE_ADDFRIENDPUSH, pmsg, strlen(pmsg), NULL, NULL, 0, 
			PNR_MSG_CACHE_TYPE_TOXA, 0, "", "");
	}

	free(pmsg);
	cJSON_Delete(rootJson);
}

/*****************************************************************************
 函 数 名  : print_message
 功能描述  : 接收好友消息回调
 输入参数  : Tox *m                 
             uint32_t friendnumber  
             TOX_MESSAGE_TYPE type  
             const uint8_t *string  
             size_t length          
             void *userdata         
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月25日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void print_message(Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type, 
    const uint8_t *string, size_t length, void *userdata)
{
    VLA(uint8_t, null_string, length + 1);
    memcpy(null_string, string, length);
    null_string[length] = 0;
    print_formatted_message(m, (char *)null_string, friendnumber);
}

/*****************************************************************************
 函 数 名  : print_message_app
 功能描述  : 处理app发送的消息
 输入参数  : Tox *m                 
             uint32_t friendnumber  
             TOX_MESSAGE_TYPE type  
             const uint8_t *string  
             size_t length          
             void *userdata         
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月25日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void print_message_app(Tox *m, uint32_t friendnumber, TOX_MESSAGE_TYPE type, 
    const uint8_t *string, size_t length, void *userdata)
{
    VLA(uint8_t, null_string, length + 1);
    memcpy(null_string, string, length);
    null_string[length] = 0;
    
    im_tox_rcvmsg_deal(m, (char *)null_string, length, friendnumber);
}

/*****************************************************************************
 函 数 名  : print_status_change
 功能描述  : 好友状态改变回调
 输入参数  : Tox *m                 
             uint32_t friendnumber  
             const uint8_t *string  
             size_t length          
             void *userdata         
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月25日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void print_status_change(Tox *m, uint32_t friendnumber, 
    const uint8_t *string, size_t length, void *userdata)
{
    int *userindex = (int *)userdata;
    char name[TOX_MAX_NAME_LENGTH + 1];

    getfriendname_terminated(m, friendnumber, name);
    if (*userindex == 0) {
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "app friend(%d)(%s) status changed to %s.", 
            friendnumber, name, string);
    } else {
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "router friend(%d)(%s) status changed to %s.", 
            friendnumber, name, string);
    }
}

/*****************************************************************************
 函 数 名  : on_friend_name
 功能描述  : 好友名称改变回调
 输入参数  : Tox *m                 
             uint32_t friendnumber  
             const uint8_t *string  
             size_t length          
             void *userdata         
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月25日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void on_friend_name(Tox *m, uint32_t friendnumber, const uint8_t *string, 
    size_t length, void *userdata)
{
#if 0
    int *userindex = (int *)userdata;
    struct im_user_struct *puser = NULL;
    
    if (*userindex == 0) {
        //save_data_new(m);
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "app friend(%d) change name to(%s)", 
            friendnumber, string);
    } else {
        puser = &g_imusr_array.usrnode[*userindex];
        save_data_new(m);
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "router friend(%d) change name to(%s)", 
            friendnumber, string);
    }
#endif
    return;
}

static Tox *load_data(void)
{
    FILE *data_file = fopen(data_file_name, "r");
    uint8_t* data = NULL;
	struct Tox_Options options;
	
    if (data_file) {
        fseek(data_file, 0, SEEK_END);
        size_t size = ftell(data_file);
        rewind(data_file);
        data = (uint8_t*)malloc(size+1);
        if(data == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"save_data_new:malloc(%d) failed",size);
            fclose(data_file);
            return 0;
        }
        memset(data,0,size);
        if (fread(data, sizeof(uint8_t), size, data_file) != size) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"[!] could not read data file!");
            fclose(data_file);
            return 0;
        }

        tox_options_default(&options);

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;
        options.savedata_data = data;
        options.savedata_length = size;
		
        Tox *m = tox_new(&options, NULL);

        if (fclose(data_file) < 0) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"[!] load_data close file(%s) failed!",data_file_name);
        }

        return m;
    } else {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"[!] load_data open file(%s) failed!",data_file_name);
    }
	free(data);
    return tox_new(NULL, NULL);
}

//暂时没用了
static int save_data(Tox *m)
{
    FILE *data_file = fopen(data_file_name, "w");

    if (!data_file) {
        perror("[!] load_key");
        return 0;
    }

    int res = 1;
    size_t size = tox_get_savedata_size(m);
    VLA(uint8_t, data, size);
    tox_get_savedata(m, data);

    if (fwrite(data, sizeof(uint8_t), size, data_file) != size) {
        fputs("[!] could not write data file (1)!", stderr);
        res = 0;
    }

    if (fclose(data_file) < 0) {
        perror("[!] could not write data file (2)");
        res = 0;
    }

    return res;
}

static void file_request_accept(Tox *tox, uint32_t friend_number, uint32_t file_number, uint32_t type,
	uint64_t file_size, const uint8_t *filename, size_t filename_length, void *user_data)
{
	int *index = (int *)user_data;
	int i = 0;
	File_Rcv *rcv = &file_rcv[*index][0];
	char filepath[512] = {0};
	int dirindex = 0;
	char *realfilename = filename;
	
	//tox save file to app's dir
	if (*index == 0) {
		for (i = 1; i <= g_imusr_array.max_user_num; i++) {
			if (g_imusr_array.usrnode[i].appid == friend_number) {
				dirindex = i;
				break;
			}
		}

		if (i == PNR_IMUSER_MAXNUM) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get friend(%d) index err.", friend_number);
			return;
		}
	} else {
		dirindex = *index;
	}

	if (type != TOX_FILE_KIND_DATA) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Refused invalid file type.");
		tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
		return;
	}

	int nowtime = time(NULL);
	for (i = 0; i < NUM_FILE_RCV; i++) {
		if (!rcv[i].file)
			break;

		//避免相同filenumber导致写入错乱
		if (nowtime - rcv[i].lastrcvtime >= 3) {
			get_file_name(rcv[i].file, filepath, sizeof(filepath));
			fclose(rcv[i].file);
			unlink(filepath);
			memset(&rcv[i], 0, sizeof(File_Rcv));
			break;
		}
	}

	if (i == NUM_FILE_RCV) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Refused exceed max rcv file num.");
        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
        return;
	}
	
	if (filename) {
		if (*index == 0) {
			if (strncmp(filename, "u:", 2)) {
				snprintf(filepath, sizeof(filepath), "%ss/%s", 
	            	g_imusr_array.usrnode[dirindex].userdata_pathurl, filename);
			} else {
				realfilename = filename + 2;
				snprintf(filepath, sizeof(filepath), "%su/%s", 
	            	g_imusr_array.usrnode[dirindex].userdata_pathurl, realfilename);				
			}
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"###rec filename(%s),filepath(%s)",filename,filepath);
		} else {
			snprintf(filepath, sizeof(filepath), "%sr/%s", 
            	g_imusr_array.usrnode[dirindex].userdata_pathurl, filename);
		}
		
		rcv[i].file = fopen(filepath, "w+");
		if (!rcv[i].file) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Refused can not create file.");
	        tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_CANCEL, 0);
	        return;
		}

		//DEBUG_PRINT(DEBUG_LEVEL_INFO, "FILE:%p--%d", rcv[i].file, i);
		
		rcv[i].lastrcvtime = time(NULL);
		rcv[i].filenumber = file_number;
		rcv[i].friendnum = friend_number;

		strncpy(rcv[i].filename, realfilename, UPLOAD_FILENAME_MAXLEN - 1);			
	}
	
   	DEBUG_PRINT(DEBUG_LEVEL_INFO, "friend_number: %u is sending us: %s--%d of size %lu\n", 
		friend_number, realfilename, file_number, file_size);

    if (tox_file_control(tox, friend_number, file_number, TOX_FILE_CONTROL_RESUME, 0)) {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "Start accept file transfer.");
	} else {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Could not accept file transfer.");
    }
}

static void file_print_control(Tox *tox, uint32_t friend_number, uint32_t file_number, 
	TOX_FILE_CONTROL control, void *user_data)
{
	int *index = (int *)user_data;
	File_Sender *sender = &file_senders[*index][0];
	
    if (control == TOX_FILE_CONTROL_CANCEL) {
        unsigned int i;

        for (i = 0; i < NUM_FILE_SENDERS; ++i) {
            /* This is slow */
            if (sender[i].file && sender[i].msg->friendnum == friend_number 
				&& sender[i].filenumber == file_number) {
                fclose(sender[i].file);
                
                sender[i].msg->filestatus = 0;
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox send file(%s) cancelled!", 
                    sender[i].msg->filename);
                
				memset(&sender[i], 0, sizeof(File_Sender));
				break;
            }
        }
    }
}

static void write_file(Tox *tox, uint32_t friendnumber, uint32_t filenumber, 
	uint64_t position, const uint8_t *data, size_t length, void *user_data)
{
	int *index = (int *)user_data;
	int i = 0;
	File_Rcv *rcv = &file_rcv[*index][0];
	char filepath[UPLOAD_FILENAME_MAXLEN * 2] = {0};
	int dirindex = 0;

	if (*index == 0) {
		for (i = 1; i <= g_imusr_array.max_user_num; i++) {
			if (g_imusr_array.usrnode[i].appid == friendnumber) {
				dirindex = i;
				break;
			}
		}

		if (i == PNR_IMUSER_MAXNUM) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get friend(%d) index err.", friendnumber);
			return;
		}

		snprintf(filepath, UPLOAD_FILENAME_MAXLEN * 2, 
			WS_SERVER_INDEX_FILEPATH "/usr%d/s/%s", dirindex, rcv->filename);
	} else {
		dirindex = *index;

		snprintf(filepath, UPLOAD_FILENAME_MAXLEN * 2, 
			WS_SERVER_INDEX_FILEPATH "/usr%d/r/%s", dirindex, rcv->filename);
	}
	
	for (i = 0; i < NUM_FILE_RCV; i++) {
		if (rcv[i].filenumber == filenumber && rcv[i].friendnum == friendnumber)
			break;
	}

	if (i == NUM_FILE_RCV) {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) get free filenumber(%d) err\n", 
            *index, filenumber);
		tox_file_control(tox, friendnumber, filenumber, TOX_FILE_CONTROL_CANCEL, 0);
		return;
	}
						
    if (length == 0) {
		fclose(rcv[i].file);
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "file(%s) transfer from friend(%u) completed\n" , 
            rcv[i].filename, friendnumber);
        memset(&rcv[i], 0, sizeof(File_Rcv));
        return;
    }
	
	fseek(rcv[i].file, position, SEEK_SET);
	//DEBUG_PRINT(DEBUG_LEVEL_INFO, "[%d]--filefd:%p--pos:%d--len:%d", i, rcv[i].file, position, length);
	if (fwrite(data, sizeof(uint8_t), length, rcv[i].file) != length) {
        fclose(rcv[i].file);
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Error writing to file(%d-%s)\n", errno, rcv[i].filename);
        memset(&rcv[i], 0, sizeof(File_Rcv));
		unlink(filepath);
		tox_file_control(tox, friendnumber, filenumber, TOX_FILE_CONTROL_CANCEL, 0);
	}

	rcv[i].lastrcvtime = time(NULL);

	return;
}
int get_ppm_usernum_by_toxfriendnum(Tox *tox, uint32_t friendnumber,int user_id,int* ppm_friendid)
{
	uint8_t fr_bin[TOX_ADDRESS_SIZE];
    char fr_str[FRADDR_TOSTR_BUFSIZE];
    int i = 0;

    if(tox == NULL)
    {
        return ERROR;
    }

	if (tox_friend_get_public_key(tox, friendnumber, fr_bin, NULL)) {
		frpuk_to_str(fr_bin, fr_str);
	}
    else
    {
        return ERROR;
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get friend pubkey(%s)",fr_str);
    for(i = 0; i< PNR_IMUSER_FRIENDS_MAXNUM; i++)
    {
        if(strncasecmp(fr_str,g_imusr_array.usrnode[user_id].friends[i].user_toxid,TOX_PUBLIC_KEY_SIZE) == OK)
        {
            *ppm_friendid = i;
            g_imusr_array.usrnode[user_id].friends[i].tox_friendnum = i;;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) get friend(%d:%s)",user_id,i,g_imusr_array.usrnode[user_id].friends[i].user_toxid);
            return OK;
        }
    }
    return ERROR;
}
static void print_online(Tox *tox, uint32_t friendnumber, TOX_CONNECTION status, void *userdata)
{
	//char name[TOX_MAX_NAME_LENGTH + 1];
    int user_id = 0;
    int ppm_friendid = 0;
    user_id = get_index_by_toxhandle(tox);
  #if 0      
	if (getfriendname_terminated(tox, friendnumber, name) != -1) {
		if (status) 
	 		DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) friend(%d:%s) went online.", user_id,friendnumber,name);
		else 
	        DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) friend(%d:%s) went offline.", user_id,friendnumber,name);
	} else {
	 	if (status) {
	        DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) friend(%d) no name went online.", 
	            user_id, friendnumber);
        } else {
		    DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) friend(%d) with no name went offline.", 
                user_id, friendnumber);
        }
	}
 #endif   
    if(get_ppm_usernum_by_toxfriendnum(tox,friendnumber,user_id,&ppm_friendid) == OK)
    {
        if (status)
        {
	 		DEBUG_PRINT(DEBUG_LEVEL_INFO, "###user(%d) friend(%d:%s) went online.",user_id,ppm_friendid,g_imusr_array.usrnode[user_id].friends[ppm_friendid].user_toxid);
            g_imusr_array.usrnode[user_id].friends[ppm_friendid].tox_onlinestatus = USER_ONLINE_STATUS_ONLINE;

        }
        else
        {
	        DEBUG_PRINT(DEBUG_LEVEL_INFO, "###user(%d) friend(%d:%s) went offline.",user_id,ppm_friendid,g_imusr_array.usrnode[user_id].friends[ppm_friendid].user_toxid);
            g_imusr_array.usrnode[user_id].friends[ppm_friendid].tox_onlinestatus = USER_ONLINE_STATUS_OFFLINE;
        }
    }
}

/*****************************************************************************
 函 数 名  : tox_connection_status
 功能描述  : tox连接状态改变
 输入参数  : Tox *tox                          
             TOX_CONNECTION connection_status  
             void *user_data                   
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月25日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void tox_connection_status(Tox *tox, TOX_CONNECTION connection_status, 
    void *user_data)
{
    char name[TOX_MAX_NAME_LENGTH + 1] = {0};
	int i = 0, friend_id = 0;
	int *index = (int *)user_data;

    tox_self_get_name(tox, (uint8_t *)name);
    
    switch (connection_status) {
    case TOX_CONNECTION_NONE:
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%s) offline", name);
        break;

    case TOX_CONNECTION_TCP:
    case TOX_CONNECTION_UDP:
		for (i = 0; i < PNR_IMUSER_FRIENDS_MAXNUM; i++) {
		   if (g_imusr_array.usrnode[*index].friends[i].exsit_flag) {
		       friend_id = get_indexbytoxid(g_imusr_array.usrnode[*index].friends[i].user_toxid);
		       if (friend_id == 0) {
		       		//避免好友关系丢失导致无法接收消息
					check_and_add_friends(tox, g_imusr_array.usrnode[*index].friends[i].user_toxid, 
						g_imusr_array.usrnode[*index].userinfo_fullurl);
				}
			}
		}
		
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%s) online proto(%d)", name, connection_status);
        break;
    }
}

int CreatedP2PNetwork(void)
{
    char idstring[200] = {0};
    Tox *m = NULL;
	int on = 0;
    int userindex = 0;
    int newdata_flag = FALSE;

    data_file_name = strcpy(dataPathFile, PNR_DAEMON_TOX_DATAFILE);
    tox_datafile_check(PNR_DEFAULT_DAEMON_USERINDEX,(char *)data_file_name,&newdata_flag);
    m = load_data();	
    if (!m) {
		m = tox_new(NULL, NULL);
    }

    qlinkNode = m;
    g_daemon_tox.ptox_handle = m;
    tox_callback_friend_request(m, auto_accept_request);
	tox_callback_friend_message(m, print_message_app);
    tox_callback_friend_name(m, on_friend_name);
    tox_callback_friend_status_message(m, print_status_change);
    tox_callback_friend_connection_status(m, print_online);
	tox_callback_self_connection_status(m, tox_connection_status);
	tox_callback_file_recv_chunk(m, write_file);
    tox_callback_file_recv_control(m, file_print_control);
    tox_callback_file_recv(m, file_request_accept);
    tox_callback_file_chunk_request(m, tox_file_chunk_request);

    get_id(m, idstring);
    strncpy(g_daemon_tox.user_toxid, idstring, TOX_ID_STR_LEN);
    g_daemon_tox.user_onlinestatus = USER_ONLINE_STATUS_ONLINE;
    g_p2pnet_init_flag = TRUE;
	DEBUG_PRINT(DEBUG_LEVEL_INFO,"get daemon tox_id(%s)",g_daemon_tox.user_toxid);
    if(newdata_flag == TRUE)
    {   
        save_data_new(m);
	}

	if (idstring[0])
		writep2pidtofile(idstring);

	/*20180124,wenchao,use Tox Bootstrap,Begin*/
	int nodeslist_ret = load_DHT_nodeslist();
	if (nodeslist_ret != 0) {
		DEBUG_PRINT(DEBUG_LEVEL_INFO,"DHT nodeslist failed to load");
	}
	/*20180124,wenchao,use Tox Bootstrap,End*/

    const char *name = "PNR_IM_SERVER";
    tox_self_set_name(m, (uint8_t *)name, strlen(name), NULL);

    //在rid起来之后创建admin用户的二维码    
    adminaccount_qrcode_init();
    while (1) {
        do_tox_connection(m);

        if (tox_self_get_connection_status(m)) {
			if (on == 0) {
                on = 1;
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"[%s] connected to DHT, check the name", name);
			}
		} else {
			if (on == 1) {
				on = 0;
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"[%s] Reconnecting to DHT", name);
			}
		}
        
        tox_iterate(m, &userindex);
		usleep(tox_iteration_interval(m) * 1000);
    }

    tox_kill(m);
	qlinkNode = NULL;
	m = NULL;
   
    return 0;
}

/*****************************************************************************
 函 数 名  : imtox_send_file
 功能描述  : 发送文件接口
 输入参数  : Tox *tox        
             int friendnum   
             char *filename  
 输出参数  : 无
 返 回 值  : 
			 ** >0 file Send ok
			 ** -1 file open fail
			 ** -2 file send fail
			 ** -3 exceed max sender
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年9月28日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int imtox_send_file(Tox *tox, struct lws_cache_msg_struct *msg, int push)
{
	uint64_t filesize;
	FILE *pf = NULL;
	uint32_t filenum;
	int i = 0;
	File_Sender *sender = &file_senders[msg->userid][0];
	char *fname = strrchr(msg->filepath, '/') + 1;
	char pathreal[512] = {0};
	char pushfilename[255] = {0};

	snprintf(pathreal, sizeof(pathreal), WS_SERVER_INDEX_FILEPATH "%s", msg->filepath);

	pf = fopen(pathreal, "rb");
	if (!pf) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open file(%s) err", pathreal);
        return -1;
    }

	fseek(pf, 0, SEEK_END);
	filesize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

    if(push == TRUE)
    {
	    snprintf(pushfilename, 255, "%s:%s", msg->fromid, fname);
    }
    else
    {
	    snprintf(pushfilename, 255, "%s", fname);
    }
	filenum = tox_file_send(tox, msg->friendnum, 
        TOX_FILE_KIND_DATA, filesize, 0, (uint8_t *)pushfilename, strlen(pushfilename), 0);
	if (filenum == -1) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox send file(%s) err", msg->filename);
        return -2;
    }

	for (i = 0; i < NUM_FILE_SENDERS; i++) {
		if (!sender[i].file)
			break;
	}

	if (i < NUM_FILE_SENDERS) {
		sender[i].file = pf;
		sender[i].filenumber = filenum;
		sender[i].friendnum = msg->friendnum;
		sender[i].msg = msg;
	} else {
	    DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox send file(%s) err, "
            "too many files send", msg->filepath);
		return -3;
	}
	
	return filenum;
}

/*****************************************************************************
 函 数 名  : imtox_send_file_to_app
 功能描述  : 直接发送文件到APP
 输入参数  : Tox *tox        
             int friendnum   
             char *fromid    
             char *filepath  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月14日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int imtox_send_file_to_app(Tox *tox, int friendnum, char *fromid, char *filepath,int msgid,int filefrom)
{
	uint64_t filesize;
	FILE *pf = NULL;
	uint32_t filenum;
	int i = 0;
	File_Sender *sender = &file_senders[0][0];
	char *fname = strrchr(filepath, '/') + 1;
	char pushfilename[255] = {0};

	pf = fopen(filepath, "rb");
	if (!pf) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open file(%s) err", filepath);
        return -1;
    }

	fseek(pf, 0, SEEK_END);
	filesize = ftell(pf);
	fseek(pf, 0, SEEK_SET);

	snprintf(pushfilename, 255, "%s:%s:%d:%d",fromid, fname,msgid,filefrom);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"imtox_send_file_to_app:send file(%s)",pushfilename);
	filenum = tox_file_send(tox, friendnum, 
        TOX_FILE_KIND_DATA, filesize, 0, (uint8_t *)pushfilename, strlen(pushfilename), 0);
	if (filenum == -1) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox send file(%s) err", filepath);
        return -2;
    }

	int nowtime = time(NULL);
	for (i = 0; i < NUM_FILE_SENDERS; i++) {
		if (!sender[i].file)
			break;

		if (nowtime - sender[i].lastsndtime >= 60) {
			fclose(sender[i].file);
			memset(&sender[i], 0, sizeof(File_Sender));
			break;
		}
	}

	if (i < NUM_FILE_SENDERS) {
		sender[i].file = pf;
		sender[i].filenumber = filenum;
		sender[i].friendnum = friendnum;
		sender[i].lastsndtime = time(NULL);
	} else {
	    DEBUG_PRINT(DEBUG_LEVEL_ERROR, "tox send file(%s) err, "
            "too many files send", filepath);
		return -3;
	}
	
	return filenum;
}

int writep2pidtofile(char *id)
{
	char filepath_name[200]= {0};
	FILE *data_file = NULL;
	
	if (!id)
		return -1;

	strcpy(filepath_name, path);
	strcat(filepath_name, DEFAULT_P2PID_FILENAME);
	data_file = fopen(filepath_name, "w");

	if (!data_file) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open file error in writep2pidtofile func");
		return -2;
	}
	
	if (fwrite(id, sizeof(uint8_t), strlen(id), data_file) != strlen(id)) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "write file error in writep2pidtofile func" );
		fclose(data_file);
		return -3;
	}

	if (fclose(data_file) < 0) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "close file error in writep2pidtofile func" );
		return -4;
	}
	
	return 0;
}

void set_timer(void)
{
	struct itimerval itv;

	itv.it_value.tv_sec = 10;
	itv.it_value.tv_usec = 0;


	itv.it_interval.tv_sec = 1*60;
	itv.it_interval.tv_usec = 0;

	setitimer (ITIMER_REAL,&itv,NULL);
}

int writep2pidtofile_new ( char* id,char* pathurl )
{
	if ( id==NULL )
	{
		return -1;
	}
	char filepath_name[200]= {0};
	strcpy ( filepath_name,pathurl);
	strcat ( filepath_name,DEFAULT_P2PID_FILENAME );
	FILE* data_file = fopen ( filepath_name, "w" );

	if ( !data_file )
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "open file error in writep2pidtofile func" );
		return -2;
	}
	if ( fwrite ( id, sizeof ( uint8_t ), strlen ( id ), data_file ) != strlen ( id ) )
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "write file error in writep2pidtofile func" );
		fclose ( data_file );
		return -3;
	}

	if ( fclose ( data_file ) < 0 )
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "close file error in writep2pidtofile func" );
		return -4;
	}
	return 0;
}

static int save_data_new(Tox *m)
{
    FILE *data_file = NULL;
    int userindex  = 0;
    int res = 1;
    char* data_filename = NULL;
    uint8_t* data = NULL;
    if(m == NULL)
    {
        return 0;
    }
    if(m == qlinkNode)
    {
        userindex = PNR_DEFAULT_DAEMON_USERINDEX;
        data_filename = dataPathFile;
    }
    else
    {
        userindex = get_index_by_toxhandle(m);
        if(userindex <= 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"save_data_new:datafile(%s) get userindex failed",data_filename);
            res = 0;
            return res;
        }
        data_filename = g_imusr_array.usrnode[userindex].userinfo_fullurl;
    }
    pthread_mutex_lock(&(g_imusr_array.usrnode[userindex].userlock));
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"save_data_new(%s)",data_filename);
    data_file = fopen(data_filename, "w");
    if (!data_file) {
        //perror("[!] load_key");
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"save_data_new:could not load datafile(%s)",data_filename);
        pthread_mutex_unlock(&(g_imusr_array.usrnode[userindex].userlock));
        return 0;
    }

    size_t size = tox_get_savedata_size(m);
    data = (uint8_t*)malloc(size+1);
    if(data == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"save_data_new:malloc(%d) failed",size);
        pthread_mutex_unlock(&(g_imusr_array.usrnode[userindex].userlock));
        return 0;
    }
    memset(data,0,size);
    //VLA(uint8_t, data, size);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"save_data_new2(user %d m:%p date %p size %d)",userindex,m,data,size);
    tox_get_savedata(m, data);
    if (fwrite(data, sizeof(uint8_t), size, data_file) != size) {
        //fputs("[!] could not write data file (1)!", stderr);
        res = 0;
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"save_data_new:could not write data file");
    }
    free(data);
    if (fclose(data_file) < 0) {
        //perror("[!] could not write data file (2)");
        res = 0;
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"save_data_new:could not close data file");
    }
    pthread_mutex_unlock(&(g_imusr_array.usrnode[userindex].userlock));
    //文件备份
    tox_datafile_backup(userindex,data_filename);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) data save version %d",userindex,g_tox_datafile[userindex].data_version);
    return res;
}
static Tox *load_data_new(char* filename)
{
    if(filename == NULL)
    {
        return NULL;
    }
    FILE *data_file = fopen(filename, "r");

    if (data_file) {
        fseek(data_file, 0, SEEK_END);
        size_t size = ftell(data_file);
        rewind(data_file);

        VLA(uint8_t, data, size);

        if (fread(data, sizeof(uint8_t), size, data_file) != size) {
            //fputs("[!] could not read data file!\n", stderr);
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"load file(%s) failed",filename);
            fclose(data_file);
            return 0;
        }
        struct Tox_Options options;

        tox_options_default(&options);
		//add by zhijie, disable local discovery,Begin

		//tox_options_set_local_discovery_enabled(&options, false);

		//add by zhijie, disable local discovery,end
		

		/*Zhijie, add to enable the TCP_relay Begin*/
		//tox_options_set_tcp_port(&options,49734);
		/*Zhijie, add to enable the TCP_relay End*/

        options.savedata_type = TOX_SAVEDATA_TYPE_TOX_SAVE;

        options.savedata_data = data;

        options.savedata_length = size;
        Tox *m = tox_new(&options, NULL);

        if (fclose(data_file) < 0) {
            //perror("[!] fclose failed");
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"close file(%s) failed",filename);
            /* we got it open and the expected data read... let it be ok */
            /* return 0; */
        }

        return m;
    }
    return tox_new(NULL, NULL);
}

/* Java_com_stratagile_qlink_qlinkcom_CreatedP2PNetwork()
** This is the entry of the p2p function, androip app must call it firstly to use the p2p.
** The function will run with while(1) loop to complete the p2p function, so it is needed to open a thread to run this function.
*/
int CreatedP2PNetwork_new(int user_index)
{
	char idstring[200] = {0};
	uint8_t name[TOX_ID_STR_LEN+1] = {0};
	Tox *m = NULL;
	struct im_user_struct *puser = NULL;
	int on = 0;
    int retime = 0;
    int newdata_flag = FALSE;

	if (user_index <= 0 || user_index > g_imusr_array.max_user_num)
		return ERROR;
	
	puser = &g_imusr_array.usrnode[user_index];
    tox_datafile_check(user_index,puser->userinfo_fullurl,&newdata_flag);
	m = load_data_new(puser->userinfo_fullurl);
	if (!m) {
		m = tox_new(NULL, NULL);
	}

	puser->ptox_handle = m;
	g_tox_linknode[user_index] = m;
	tox_callback_friend_request(m, friend_request_cb);
	tox_callback_friend_message(m, print_message);
	tox_callback_friend_name(m, on_friend_name);
	tox_callback_friend_status_message(m, print_status_change);
	tox_callback_friend_connection_status(m, print_online);
	tox_callback_self_connection_status(m, tox_connection_status);
	tox_callback_file_recv_chunk(m, write_file);
	tox_callback_file_recv_control(m, file_print_control);
	tox_callback_file_recv(m, file_request_accept);
	tox_callback_file_chunk_request(m, tox_file_chunk_request);

	get_id(m, idstring);
	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) init_flag(%d) id(%s)",user_index,puser->init_flag,idstring);

	if (puser->init_flag == FALSE) {
#if 0//这里预留将来修改同步data的逻辑
		if(puser->user_toxid[0] == 0)
		{
			strncpy(puser->user_toxid,idstring,TOX_ID_STR_LEN);
			pnr_usr_instance_insert(user_index);
		}
#else
		strncpy(puser->user_toxid,idstring,TOX_ID_STR_LEN);
	    save_data_new(m);
		pnr_usr_instance_insert(user_index);
#endif
		puser->init_flag = TRUE;
    }
	puser->user_onlinestatus = USER_ONLINE_STATUS_ONLINE;
	imuser_friendstatus_push(user_index,USER_ONLINE_STATUS_ONLINE);
	DEBUG_PRINT(DEBUG_LEVEL_INFO,"new user(%d:%s) tox(%p)online",puser->user_index,puser->user_toxid,m);

	if (idstring[0])
		writep2pidtofile_new(idstring,puser->userinfo_pathurl);

	int nodeslist_ret = load_DHT_nodeslist();
	if (nodeslist_ret) {
		DEBUG_PRINT(DEBUG_LEVEL_INFO,"DHT nodeslist failed to load");
	}
    
	strcpy((char *)name,puser->user_name);
	tox_self_set_name(m, name, strlen((char *)name), NULL);

	while (1) {
		do_tox_connection(m);
        retime++;
		if (tox_self_get_connection_status(m)) {
			if (on == 0) {
                on = 1;
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"[%d:%s:%s] connected to DHT, check the name",
					retime,puser->user_name,puser->user_toxid);
                retime = 0;
			}
		} else {
			if (on == 1) {
				on = 0;
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"[%s:%s] Reconnecting to DHT",
                    puser->user_name,puser->user_toxid);
			}
		}
		
		tox_iterate(m, &user_index);
		usleep(tox_iteration_interval(m) * 1000);
	}

	tox_kill(m);
	m = NULL;
   
	return 0;
}

//added by willcao



/* GetFriendNumInFriendlist_new
** Input the friend ID and get the friend num back
** After the app get the friend p2p ID from the block chain, app may call this function the get the friendnum
** The friend num may be quite useful in the other function
** -1 qlinkNode is not valid
** -2 invalid input friendId
** -3 friend not in list
** >=0 the friend num
*/
int GetFriendNumInFriendlist_new(Tox * plinknode,char * friendId_P)
{
	uint8_t *friendId_bin;
	int friendLoc;
	
	if (plinknode) {
		if (!friendId_P)
			return -2;

		friendId_bin = hex_string_to_bin(friendId_P);
		friendLoc = tox_friend_by_public_key(plinknode, friendId_bin, NULL);
		//DEBUG_PRINT(DEBUG_LEVEL_INFO,"Get friend(%s) num is %d",friendId_P, friendLoc);

		free(friendId_bin);

		if (friendLoc == -1) 
			return -3;
		else
			return friendLoc;
	}
	
	return -1;
}


/* AddFriend_new
** 
** the friend p2pid has the same strcture of its own p2pid, see the Java_com_stratagile_qlink_qlinkcom_ReturnOwnP2PId() for detail
** for example : 2EADC1764978270C0750374D1C1913226D84B41C652FE132AA8FBA3FEAC51D77C265812D4746
** After the app seached the local wifi, call the blockchain sdk with the parameters of wifi SSID+MAC and get the friend p2p ID
** Call this function to add p2p friend with the parameter of the friend p2pid
** And then the p2p function will try to monitor if it is ok to build a peer to peer connection with this friend
** 
** -1 qlinkNode is not valid
** -2 invalid friendid address
** num is this location of friend in friend list, for example, if this is the 1st friend, num is 0, 2nd friend, num is 1.
*/

int check_and_add_friends(Tox * plinknode,char * friendid_p,char* datafile)
{
	int friendLoc;
	
	if (plinknode) {
		if (!friendid_p)
			return -2;

		friendLoc=GetFriendNumInFriendlist_new(plinknode,friendid_p);
		if (friendLoc >= 0) 
            return friendLoc;

        unsigned char *bin_string = hex_string_to_bin(friendid_p);
        TOX_ERR_FRIEND_ADD error;
        uint32_t num = tox_friend_add(plinknode, bin_string, (const uint8_t *)"Hi WIFI friend", sizeof("Hi WIFI friend"), &error);
        free(bin_string);
        char numstring[100] = {0};

        switch (error) {
            case TOX_ERR_FRIEND_ADD_TOO_LONG:
                sprintf(numstring, "[i] Message is too long.");
                break;

            case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
                sprintf(numstring, "[i] Please add a message to your request.");
                break;

            case TOX_ERR_FRIEND_ADD_OWN_KEY:
                sprintf(numstring, "[i] That appears to be your own ID.");
                break;

            case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
                sprintf(numstring, "[i] Friend request already sent.");
                break;

            case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
                sprintf(numstring, "[i] Address has a bad checksum.");
                break;

            case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
                sprintf(numstring, "[i] New nospam set.");
                break;

            case TOX_ERR_FRIEND_ADD_MALLOC:
                sprintf(numstring, "[i] malloc error.");
                break;

            case TOX_ERR_FRIEND_ADD_NULL:
                sprintf(numstring, "[i] message was NULL.");
                break;

            case TOX_ERR_FRIEND_ADD_OK:
                sprintf(numstring, "[i] Added friend as %d.", num);
                save_data_new(plinknode);
                break;
        }

        DEBUG_PRINT(DEBUG_LEVEL_INFO,"%s",numstring);
		return num;
    }
	else 
		return -1;
}

/*****************************************************************************
 函 数 名  : add_friends_force
 功能描述  : 强制重新添加好友
 输入参数  : Tox *plinknode  
             char *friendid  
             char *datafile  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月4日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int add_friends_force(Tox *plinknode, char *friendid, char *msg)
{
	int friendLoc;
	
	if (plinknode) {
		if (!friendid)
			return -2;

		friendLoc = GetFriendNumInFriendlist_new(plinknode, friendid);
		if (friendLoc >= 0) {
            tox_friend_delete(plinknode, friendLoc, NULL);
		}

        unsigned char *bin_string = hex_string_to_bin(friendid);
        TOX_ERR_FRIEND_ADD error;
        uint32_t num = tox_friend_add(plinknode, bin_string, (const uint8_t *)msg, strlen(msg), &error);
        free(bin_string);
        char numstring[100] = {0};

        switch (error) {
            case TOX_ERR_FRIEND_ADD_TOO_LONG:
                sprintf(numstring, "[i] Message is too long.");
                break;

            case TOX_ERR_FRIEND_ADD_NO_MESSAGE:
                sprintf(numstring, "[i] Please add a message to your request.");
                break;

            case TOX_ERR_FRIEND_ADD_OWN_KEY:
                sprintf(numstring, "[i] That appears to be your own ID.");
                break;

            case TOX_ERR_FRIEND_ADD_ALREADY_SENT:
                sprintf(numstring, "[i] Friend request already sent.");
                break;

            case TOX_ERR_FRIEND_ADD_BAD_CHECKSUM:
                sprintf(numstring, "[i] Address has a bad checksum.");
                break;

            case TOX_ERR_FRIEND_ADD_SET_NEW_NOSPAM:
                sprintf(numstring, "[i] New nospam set.");
                break;

            case TOX_ERR_FRIEND_ADD_MALLOC:
                sprintf(numstring, "[i] malloc error.");
                break;

            case TOX_ERR_FRIEND_ADD_NULL:
                sprintf(numstring, "[i] message was NULL.");
                break;

            case TOX_ERR_FRIEND_ADD_OK:
                sprintf(numstring, "[i] Added friend as %d.", num);
                save_data_new(plinknode);
                break;
        }

        DEBUG_PRINT(DEBUG_LEVEL_INFO, "%s", numstring);
		return num;
    } else {
		return -1;
	}
}

int get_index_by_toxhandle(Tox* ptox)
{
    int i = 0;
    for(i=1;i<=PNR_IMUSER_MAXNUM;i++)
    {
        if(g_imusr_array.usrnode[i].ptox_handle == ptox)
        {
            return i;
        }
    }
    return 0;
}

int get_friendid_bytoxid(int userid,char* friend_name)
{
    int i = 0;

    if( userid <=0 || userid > PNR_IMUSER_MAXNUM || friend_name == NULL || strlen(friend_name) != TOX_ID_STR_LEN)
    {
        return -1;
    }
    
    for(i=0;i<PNR_IMUSER_FRIENDS_MAXNUM;i++)
    {
        if(strcmp(friend_name,g_imusr_array.usrnode[userid].friends[i].user_toxid) == OK)
        {
            return i;
        }
    }
    
    return -1;
}

/*****************************************************************************
 函 数 名  : if_friend_available
 功能描述  : 是否
 输入参数  : int userindex   
             char *friendid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月24日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int if_friend_available(int userindex, char *friendid)
{
	int id = 0;

	id = get_friendid_bytoxid(userindex, friendid);
	if (id == -1) {
		return 0;
	}

	if (g_imusr_array.usrnode[userindex].friends[id].oneway)
		return 0;

	return 1;
}
/*****************************************************************************
 函 数 名  : insert_tox_file_msgnode
 功能描述  : 插入tox文件传输消息到缓存
 输入参数  : int userid      
             char *from      
             char *to        
             char *pmsg      
             int msglen      
             char *filepath  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月22日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int insert_tox_file_msgnode(int userid, char *from, char *to,
    char *pmsg, int msglen, char *filename, char *filepath, int type, 
    int logid, int msgid, int ftype,char* skey, char* dkey)
{
    DEBUG_PRINT(DEBUG_LEVEL_INFO, "add tox file cache!msgid(%d)", msgid);
    
    return pnr_msgcache_dbinsert(msgid, from, to, type, 
        pmsg, msglen, filename, filepath, logid, PNR_MSG_CACHE_TYPE_TOXF, ftype, skey, dkey);
}

/*****************************************************************************
 函 数 名  : insert_tox_msgnode
 功能描述  : 插入数据库消息缓存
 输入参数  : int userid  
             char* from  
             char*to     
             char* pmsg  
             int msglen  
             int limit  重传次数 0表示不限
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月22日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int insert_tox_msgnode(int userid, char *from, char *to,
    char *pmsg, int msglen, int type, int logid, int msgid,char* skey, char* dkey)
{
    int toxfriend_id = 0;//tox链表里的
    char *ptox_msg = NULL;
    int ret = 0;

    if (userid <=0 || userid > PNR_IMUSER_MAXNUM
        ||from == NULL || to == NULL || pmsg == NULL) {
        return -1;
    }

    toxfriend_id = check_and_add_friends(g_tox_linknode[userid], to, 
		g_imusr_array.usrnode[userid].userinfo_fullurl);
    if (toxfriend_id < 0) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d)find friend(%s) ret %d error",userid,to,toxfriend_id);
        pnr_msgcache_dbdelete(msgid, 0);
        return -1;
    }

	cJSON *ret_root = cJSON_CreateObject();
    if (!ret_root) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"insert_tox_msgnode err");
        pnr_msgcache_dbdelete(msgid, 0);
        return -1;
    }
    
    cJSON_AddItemToObject(ret_root, "type", cJSON_CreateString(immsgForward));
    cJSON_AddItemToObject(ret_root, "user", cJSON_CreateString(to));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)msgid));
    cJSON_AddItemToObject(ret_root, "data", cJSON_CreateString(pmsg));
    //这里消息内容不能做转义，要不然对端收到会出错
    ptox_msg = cJSON_PrintUnformatted_noescape(ret_root);

    DEBUG_PRINT(DEBUG_LEVEL_INFO, "add tox msg cache!msgid(%d)", msgid);
    pnr_msgcache_dbinsert(msgid, from, to, type, 
        ptox_msg, strlen(ptox_msg), NULL, NULL, logid, PNR_MSG_CACHE_TYPE_TOX, 0, skey, dkey);
        
    free(ptox_msg);
    cJSON_Delete(ret_root);
    return ret;
}
/*****************************************************************************
 函 数 名  : insert_tox_file_msgnode_v3
 功能描述  : 插入tox文件传输消息到缓存
 输入参数  : int userid      
             char *from      
             char *to        
             char *pmsg      
             int msglen      
             char *filepath  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月22日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int insert_tox_file_msgnode_v3(int userid, char *from, char *to,
    char *pmsg, int msglen, char *filename, char *filepath, int type, 
    int logid, int msgid, int ftype,char* sign, char* nonce,char* prikey)
{
    DEBUG_PRINT(DEBUG_LEVEL_INFO, "add tox file cache!msgid(%d)", msgid);
    
    return pnr_msgcache_dbinsert_v3(msgid, from, to, type, 
        pmsg, msglen, filename, filepath, logid, PNR_MSG_CACHE_TYPE_TOXF, ftype, sign, nonce, prikey);
}
/*****************************************************************************
 函 数 名  : insert_tox_msgnode_v3
 功能描述  : 插入数据库消息缓存
 输入参数  : int userid  
             char* from  
             char*to     
             char* pmsg  
             int msglen  
             int limit  重传次数 0表示不限
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月22日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int insert_tox_msgnode_v3(int userid, char *from, char *to,
    char *pmsg, int msglen, int type, int logid, int msgid,char* sign, char* nonce, char* prikey)
{
    int toxfriend_id = 0;//tox链表里的
    char *ptox_msg = NULL;
    int ret = 0;

    if (userid <=0 || userid > PNR_IMUSER_MAXNUM
        ||from == NULL || to == NULL || pmsg == NULL) {
        return -1;
    }

    toxfriend_id = check_and_add_friends(g_tox_linknode[userid], to, 
		g_imusr_array.usrnode[userid].userinfo_fullurl);
    if (toxfriend_id < 0) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d)find friend(%s) ret %d error",userid,to,toxfriend_id);
        pnr_msgcache_dbdelete(msgid, 0);
        return -1;
    }

	cJSON *ret_root = cJSON_CreateObject();
    if (!ret_root) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"insert_tox_msgnode err");
        pnr_msgcache_dbdelete(msgid, 0);
        return -1;
    }
    
    cJSON_AddItemToObject(ret_root, "type", cJSON_CreateString(immsgForward));
    cJSON_AddItemToObject(ret_root, "user", cJSON_CreateString(to));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)msgid));
    cJSON_AddItemToObject(ret_root, "data", cJSON_CreateString(pmsg));
    //这里消息内容不能做转义，要不然对端收到会出错
    ptox_msg = cJSON_PrintUnformatted_noescape(ret_root);

    DEBUG_PRINT(DEBUG_LEVEL_INFO, "add tox msg cache!msgid(%d)", msgid);
    pnr_msgcache_dbinsert_v3(msgid, from, to, type, 
        ptox_msg, strlen(ptox_msg), NULL, NULL, logid, PNR_MSG_CACHE_TYPE_TOX, 0, sign, nonce, prikey);
        
    free(ptox_msg);
    cJSON_Delete(ret_root);
    return ret;
}

/*****************************************************************************
 函 数 名  : tox_msg_response
 功能描述  : tox消息回复
 输入参数  : cJSON* pJson  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月18日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int tox_msg_response(Tox *m, cJSON *pJson, int friendnum)
{
    cJSON *msgid = cJSON_GetObjectItem(pJson, "msgid");
    cJSON *ret = NULL;
    char *msg = NULL;

    ret = cJSON_CreateObject();
    if (!ret) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create json err");
        return -1;
    }

    if (!msgid) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get msgid err");
        return -1;
    }

    cJSON_AddItemToObject(ret, "type", cJSON_CreateString(immsgForwardRes));
    cJSON_AddItemToObject(ret, "msgid", cJSON_CreateNumber(msgid->valueint));

    msg = cJSON_PrintUnformatted(ret);

    tox_friend_send_message(m, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
        (uint8_t *)msg, strlen(msg), NULL);

    free(msg);
    cJSON_Delete(ret);
    return OK;
}

/*****************************************************************************
 函 数 名  : processImMsgForwardRes
 功能描述  : 处理tox确认消息
 输入参数  : Tox *m         
             cJSON *pJson   
             int friendnum  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月18日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int processImMsgForwardRes(Tox *m, cJSON *pJson, int friendnum)
{
    char toxid[TOX_ID_STR_LEN + 1] = {0};
    int id = 0;
    cJSON *msgid = cJSON_GetObjectItem(pJson, "msgid");

    get_id(m, toxid);
    id = get_indexbytoxid(toxid);

    DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get tox msg response!"
        "user(%d) msgid(%d)", id, msgid->valueint);

    pnr_msgcache_dbdelete(msgid->valueint, id);
    return OK;
}

int processImMsgForward(Tox *m, cJSON *pJson, int friendnum)
{
    cJSON* data_info = NULL;
    cJSON* user_info = NULL;
    char* pmsg = NULL;
    char* pusr = NULL;
    int index = 0;
    
	if (NULL == pJson)
	{
		return -1;
	}

    tox_msg_response(m, pJson, friendnum);
    
    user_info = cJSON_GetObjectItem ( pJson, "user" );
    if(user_info == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"find user fail");
        return ERROR;
    }
    pusr = user_info->valuestring;
    index = get_indexbytoxid(pusr);
    if(index == 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"find user(%s) fail",pusr);
        return ERROR;
    }
    if(g_imusr_array.usrnode[index].init_flag != TRUE
        || memcmp(g_imusr_array.usrnode[index].user_toxid,pusr,TOX_ID_STR_LEN)!= OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"find user(%s:%d) fail",pusr,index);
        return ERROR;
    }
    data_info = cJSON_GetObjectItem ( pJson, "data" );
	if ( NULL == data_info )
	{
		return -2;
	}
	pmsg =  data_info->valuestring;
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"#####get msg(%s)",pmsg);

    imtox_pushmsg_predeal(index,pusr,pmsg,strlen(pmsg));
    
	return 0;
}
int tox_datafile_check(int user_index,char* datafile,int* newdata_flag)
{
    char tmpdata_md5value[PNR_MD5_VALUE_MAXLEN+1] = {0};
    char sys_cmd[CMD_MAXLEN] = {0};
    if(datafile == NULL || user_index < 0 || user_index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    if(g_tox_datafile[user_index].data_version == 0)
    {
        *newdata_flag = TRUE;
        return OK;
    }
    if(access(datafile,F_OK) != OK)
    {
        if(access(g_tox_datafile[user_index].datafile_bakpath,F_OK) == OK)
        {
            snprintf(sys_cmd,CMD_MAXLEN,"cp -f %s %s",g_tox_datafile[user_index].datafile_bakpath,g_tox_datafile[user_index].datafile_curpath);
            system(sys_cmd);   
            return OK;
        }
        else
        {
            *newdata_flag = TRUE;
            return OK;
        }
    }
    md5_hash_file(datafile,tmpdata_md5value);
    if(strncasecmp(tmpdata_md5value,g_tox_datafile[user_index].datafile_md5,PNR_MD5_VALUE_MAXLEN) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) datafile changed,reload(%s->%s)",user_index,g_tox_datafile[user_index].datafile_bakpath,g_tox_datafile[user_index].datafile_curpath);
        snprintf(sys_cmd,CMD_MAXLEN,"cp -f %s %s",g_tox_datafile[user_index].datafile_bakpath,g_tox_datafile[user_index].datafile_curpath);
        system(sys_cmd);
    }
    return OK;
}

int tox_datafile_backup(int user_index,char* datafile)
{
    int old_data_version = 0;    
    char tmpdata_md5value[PNR_MD5_VALUE_MAXLEN+1] = {0};
    char sys_cmd[CMD_MAXLEN] = {0};
    if(datafile == NULL || user_index < 0 || user_index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    if(access(datafile,F_OK) != OK)
    {
        return ERROR;
    }
    old_data_version = g_tox_datafile[user_index].data_version;    
    md5_hash_file(datafile,tmpdata_md5value);
    if(strncasecmp(tmpdata_md5value,g_tox_datafile[user_index].datafile_md5,PNR_MD5_VALUE_MAXLEN) != OK)
    {
        g_tox_datafile[user_index].data_version++;
        if(old_data_version == 0)
        {
            memset(&g_tox_datafile[user_index],0,sizeof(struct pnr_tox_datafile_struct));
            g_tox_datafile[user_index].user_index = user_index;
            g_tox_datafile[user_index].data_version = PNR_DEFAULT_DATAVERSION;
            if(user_index == PNR_DEFAULT_DAEMON_USERINDEX)
            {
                strcpy(g_tox_datafile[user_index].toxid,g_daemon_tox.user_toxid);
            }
            else
            {
                strcpy(g_tox_datafile[user_index].toxid,g_imusr_array.usrnode[user_index].user_toxid);
            }
            strcpy(g_tox_datafile[user_index].datafile_md5,tmpdata_md5value);
            strcpy(g_tox_datafile[user_index].datafile_curpath,datafile);
            strcpy(g_tox_datafile[user_index].datafile_bakpath,datafile);
            strcat(g_tox_datafile[user_index].datafile_bakpath,"_bak");
            pnr_tox_datafile_dbinsert(user_index);
        }
        else
        {
            strcpy(g_tox_datafile[user_index].datafile_md5,tmpdata_md5value);
            pnr_tox_datafile_md5update_byid(user_index,g_tox_datafile[user_index].data_version,g_tox_datafile[user_index].datafile_md5);
        }
        snprintf(sys_cmd,CMD_MAXLEN,"cp -f %s %s",datafile,g_tox_datafile[user_index].datafile_bakpath);
        system(sys_cmd);  
    }
    return OK;
}
