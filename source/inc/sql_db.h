#ifndef SQL_DB_H
#define SQL_DB_H
#include <stdio.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include <sys/types.h>
#include <sqlite3.h>
#include <common_lib.h>
#include "pn_imserver.h"

#define SQL_CMD_LEN 2048
#define MSGSQL_CMD_LEN 4096

enum DB_VERSION_ENUM
{
	DB_VERSION_V1=1,
	DB_VERSION_V2=2,
    DB_VERSION_V3=3,
};
#define DB_VERSION_KEYWORD     "datebase_version"
#define DB_IMUSER_MAXNUM_KEYWORDK     "imuser_maxnum"
#define DB_TEMPACCOUNT_USN_KEYWORD     "temp_account_usn"
#define DB_DEVLOGINEKEY_KEYWORD     "dev_loginkey"
//默认设备登陆密码，qlcadmin的sha256加密
#define DB_DEFAULT_DEVLOGINKEY_VALUE "90d5c0dd1b35f8b568d9bc9202253162e1699671367ba87af364754f00e8778e"
#define DB_CURRENT_VERSION    DB_VERSION_V3

struct db_string_ret
{
    int buf_len;
    char* pbuf;
};

int sql_db_init(void);
int sql_friendsdb_init(void);
int sql_msglogdb_init(int index);
int pnr_msglog_getid(int index, int *logid);
int pnr_msglog_delid(int index, int logid);
int sql_msgcachedb_init(int index);
int sql_db_check(void);
int32 dbget_int_result(void* obj, int n_columns, 
    char** column_values,char** column_names);
int32 dbget_singstr_result(void* obj, int n_columns, 
    char** column_values,char** column_names);
int pnr_usr_instance_get(int index);
int pnr_usr_instance_insert(int index);
int pnr_dbget_friendsall_byuserid(int id,char* userid);
int pnr_friend_dbinsert(char* from_toxid,char* to_toxid,char* nickname,char* userkey);
int pnr_friend_dbdelete(char* from_toxid,char* to_toxid,int oneway);
int pnr_friend_dbupdate_nicename_bytoxid(char* from_toxid,char* to_toxid,char* nickname);
int pnr_friend_dbupdate_remarks_bytoxid(char* from_toxid,char* to_toxid,char* remarks);
int pnr_friend_get_remark(char *userid, char *friendid, char *value, int len);
int pnr_msglog_dbinsert(int recode_userindex,int msgtype,int log_id, int msgstatus,
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext,int ext2);
int pnr_msglog_dbinsert_specifyid(int recode_userindex,int msgtype,int db_id,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext, int ext2);
int pnr_msglog_dbupdate(int recode_userindex,int msgtype,int log_id,int msgstatus,
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext,int ext2);
int pnr_msglog_dbdelete(int recode_userindex,int msgtype,int log_id, 
    char* from_toxid,char* to_toxid);
int pnr_account_dbupdate_lastactive_bytoxid(char* p_toxid);
int pnr_msgcache_dbinsert(int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, char *filename, char *filepath, int logid, int ctype, int ftype,char* skey,char* dkey);
int pnr_msgcache_dbdelete(int msgid, int userid);
int pnr_msgcache_dbdelete_nolock(struct lws_cache_msg_struct *msg);
int pnr_msgcache_dbdelete_by_friendid(int index, char *friendid);
int pnr_msgcache_getid(int index, int *msgid);
int pnr_msgcache_init(void);
int pnr_msgcache_dbinsert_push(int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, char *filename, char *filepath, int logid, int ctype, int ftype,char* skey,char* dkey);
int sql_adminaccount_init(void);
int sql_tempaccount_sn_init(void);
int pnr_account_init_fromdb(void);
int pnr_account_dbinsert(struct pnr_account_struct* p_account);
int pnr_account_tmpuser_dbinsert(struct pnr_account_struct* p_account);
int pnr_account_dbupdate(struct pnr_account_struct* p_account);
int pnr_account_dbupdate_bytoxid(struct pnr_account_struct* p_account);
int pnr_account_get_byusn(struct pnr_account_struct* p_account);
int pnr_account_dbget_byuserid(struct pnr_account_struct* p_account);
int pnr_filelog_delete_byfiletype(int filetype,char* user_id,char* friend_id);
int pnr_tox_datafile_dbget(void* obj, int n_columns, char** column_values,char** column_names);
int pnr_tox_datafile_dbinsert(int index);
int pnr_tox_datafile_md5update_byid(int userindex,int data_version,char* md5);
int pnr_tox_datafile_init_fromdb(void);
int pnr_msgcache_dbdelete_by_logid(int index, struct im_sendmsg_msgstruct *msg);
int pnr_msglog_dbupdate_stauts_byid(int index,int db_id,int msgstatus);
int pnr_msglog_dbget_logid_byid(int index,int id,int* logid);
int pnr_msglog_dbget_dbid_bylogid(int index,int log_id,char* from,char* to,int* db_id);
int pnr_devloginkey_dbupdate(char* loginkey);
int pnr_account_dbupdate_idcode_byusn(struct pnr_account_struct* p_account);
int pnr_friend_get_pubkey_bytoxid(char *userid, char *friendid, char *pubkey);
#endif

