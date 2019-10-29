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
#define MSGSQL_ALLOC_MAXLEN  60000

enum DB_VERSION_ENUM
{
	DB_VERSION_V1=1,
	DB_VERSION_V2=2,
    DB_VERSION_V3=3,
    DB_VERSION_V4=4,
    DB_VERSION_V5=5,
    DB_VERSION_V6=6,
    DB_VERSION_V7=7,
    DB_VERSION_V8=8,
    DB_VERSION_V9=9,
    DB_VERSION_V10=10,
    DB_VERSION_V11=11,
    DB_VERSION_V12=12,
};
#define DB_VERSION_KEYWORD     "datebase_version"
#define DB_IMUSER_MAXNUM_KEYWORDK     "imuser_maxnum"
#define DB_TEMPACCOUNT_USN_KEYWORD     "temp_account_usn"
#define DB_DEVLOGINEKEY_KEYWORD     "dev_loginkey"
#define DB_DEVNAME_KEYWORD     "dev_name"
#define DB_PUBNETMODE_KEYWORD "pubnet_mode"
#define DB_FRPMODE_KEYWORD "frp_mode"
#define DB_FRPPORT_KEYWORD "frp_port"
#define DB_PUBNET_IPSTR_KEYWORD "pubnet_ip"
#define DB_PUBNET_PORT_KEYWORD  "pubnet_port"
#define DB_PUBNET_SSHPORT_KEYWORD "pubnet_sshport"
#define DB_USER_CAPACITY_KEYWORD  "user_capacity"
//默认设备登陆密码，qlcadmin的sha256加密
#define DB_DEFAULT_DEVLOGINKEY_VALUE "90d5c0dd1b35f8b568d9bc9202253162e1699671367ba87af364754f00e8778e"
//默认设备名称，base64转码
#define DB_DEFAULT_DEVNAME_VALUE "VW5pbml0aWFsaXplZA=="
#define DB_CURRENT_VERSION    DB_VERSION_V12
struct db_string_ret
{
    int buf_len;
    char* pbuf;
};
struct unode_idstruct
{
    int local;
    int uid;
    int fid;
};
int sql_db_init(void);
int sql_friendsdb_init(void);
int sql_groupinfodb_init(void);
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
int pnr_msglog_dbinsert_specifyid_v3(int recode_userindex,int msgtype,int db_id,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* sign,char* nonce,char* prikey,char* pext, int ext2);
int pnr_msglog_dbinsert_specifyid(int recode_userindex,int msgtype,int db_id,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext, int ext2);
int pnr_msglog_dbupdate(int recode_userindex,int msgtype,int log_id,int msgstatus,
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext,int ext2);
int pnr_msglog_dbupdate_v3(int recode_userindex,int msgtype,int log_id,int msgstatus,
    char* from_toxid,char* to_toxid,char* pmsg,char* sign,char* nonce,char* prikey,char* pext, int ext2);
int pnr_msglog_dbdelete(int recode_userindex,int msgtype,int log_id, 
    char* from_toxid,char* to_toxid);
int pnr_account_dbupdate_lastactive_bytoxid(char* p_toxid);
int pnr_msgcache_dbinsert(int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, char *filename, char *filepath, int logid, int ctype, int ftype,char* skey,char* dkey);
int pnr_msgcache_dbinsert_v3(int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, char *filename, char *filepath, int logid, int ctype, 
    int ftype,char* sign,char* nonce,char* prikey);
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
int pnr_account_dbupdate_dbinfo_bytoxid(struct pnr_account_struct* p_account);
int pnr_account_get_byusn(struct pnr_account_struct* p_account);
int pnr_account_dbget_byuserkey(struct pnr_account_struct* p_account);
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
int pnr_msglog_dbget_byid(int index,int db_id,struct im_sendmsg_msgstruct* pmsg);
int pnr_msglog_dbupdate_filename_byid(int uindex,int dbid,char* filename, char* filepath);
int pnr_devloginkey_dbupdate(char* loginkey);
int pnr_account_dbupdate_idcode_byusn(struct pnr_account_struct* p_account);
int pnr_friend_get_pubkey_bytoxid(char *userid, char *friendid, char *pubkey);
int pnr_devname_dbupdate(char* new_name);
int pnr_userdev_mapping_dbupdate(char* user_id,char* dev_id,char* dev_name);
int32 pnr_usrdev_mappinginfo_sqlget(struct im_userdev_mapping_struct* p_info);
int pnr_account_dbcheck_bypubkey(struct pnr_account_struct* p_account);
int pnr_userdev_mapping_dbupdate_bydevid(char* dev_id,char* dev_name);
int pnr_userinfo_dbget_byuserid(struct pnr_userinfo_struct* puser);
int pnr_userinfo_dbupdate(struct pnr_userinfo_struct* puser);
int pnr_groupuser_dbinsert(int gid,int uid,int uindex,int type,int msgid,char* utoxid,char* name,char* userkey);
int pnr_groupuser_dbdelete_byuid(int gid,int uid);
int pnr_groupuser_gremark_dbupdate_byid(int gid,int uindex,char* gname);
int pnr_groupuser_lastmsgid_dbupdate_byid(int gid,int uindex,int last_msgid);
int pnr_group_dbinsert(int gid,int uindex,int verify,char* utoxid,char* name,char* group_hid);
int pnr_group_dbdelete_bygid(int gid);
int pnr_groupverify_dbupdate_bygid(int gid,int verify);
int pnr_groupname_dbupdate_bygid(int gid,char* gname);
int pnr_groupmsg_dbinsert(int gid,int uindex,int msgid,int type,char* sender,char* msg,char* attend,char* ext,char* ext2,char* p_filekey,int associd);
int pnr_groupmsg_dbdelete_bymsgid(int gid,int msgid);
int pnr_groupmsg_dbget_lastmsgid(int gid,int* pmsgid);
int pnr_groupmsg_dbget_bymsgid(int gid,int msgid,struct group_user_msg* pmsg);
int pnr_groupoper_dbget_insert(int gid,int action,int fromid,int toid,char* gname,char* from,char* to,char* ext);
int pnr_netconfig_dbget(struct pnrdev_netconn_info* pinfo);
int dbupdate_strvalue_byname(sqlite3 * pdb,char* table_name, char* key_name,char* key_var);
int dbupdate_intvalue_byname(sqlite3 * pdb,char* table_name, char* key_name,int key_var);
int pnr_logcache_dbinsert(int cmd,char* fromid,char* toid,char* msg,char* ext);
int pnr_usr_instance_dbdelete_bytoxid(char* toxid);
int pnr_friend_delete_bytoxid(char *userid);
int pnr_userdev_mapping_dbdelte_byusrid(char* usrid);
int pnr_account_dbdelete_byuserid(char* userid);
int pnr_userinfo_dbdelete_byuserid(char* usrid);
int pnr_tox_datafile_dbdelete_bytoxid(char* toxid);
int pnr_normal_account_dbdelete_byusn(char* usn);
// email 操作
int pnr_emconfig_uindex_dbget_byuser(char *gname,int *uindex);
int pnr_emconfig_num_dbget_byuindex(int uindex,int *count);
int pnr_email_config_dbinsert(int uindex,struct email_config_mode config_mode);
int pnr_email_config_dbupdate(int uindex,struct email_config_mode config_mode);
int pnr_email_config_dbcheckcount(int uindex,char *gname,int *count);
int pnr_email_config_dbdel(int uindex,char *emailName);
int pnr_email_config_dbupdatesign(int uindex,char *emailName,char *emailSign);
int pnr_email_list_dbinsert(struct email_model* emailMode);
int pnr_emlist_mailnum_dbget_byuser(char *gname,int *p_count);
int pnr_emailfile_dbdelete_byid(int uindex,int mailid);
int pnr_emaillist_dbdelete_byid(int uindex,int mailid);
int pnr_email_config_dbupdatesign(int uindex,char *emailName,char *emailSign);
int pnr_email_file_dbdel(int uindex,int emailid);
int pnr_email_list_dbdel_emailname(int uindex,char *emailName);
int pnr_email_file_dbdel_emailname(int uindex,char *emailName);
int pnr_emaillist_dbnumget_byuuid(struct email_model* emailMode,int* p_count);
int pnr_email_ukey_dbget_byemname(char* em_name,char* ukey,int* found_flag);
int pnr_email_config_dbupdatelable(int uindex,int status,int mailid);
int pnr_email_config_dbupdateread(int uindex,int status,int mailid);
int pnr_user_capacity_dbupdate(int index,unsigned int capacity);
int pnr_emconfig_mails_dbget_byuindex(int uindex,char* pmails);
int sql_emaillinfodb_init(void);
//新增cfd_uinfo_tbl操作
int cfd_update_uinfotbl(void);
int cfg_getmails_byuindex(int uindex,char* mailslist);
int cfd_dbfuzzyget_uindex_bymailinfo(int* uid,int* fid,int* local,char* mailinfo);
int cfd_dbupdate_uinfonickname_byuid(int uid,int fid,int local,char* nickname);
int cfd_dbupdate_uinfomailinfo_byuid(int uid,int fid,int local,int mailseq,char* mailinfo);
int cfd_dbinsert_uinfo_newrecord(struct cfd_userinfo_struct* pnode);
int cfd_dbdelete_uinfo_byuid(int uid,int fid,int local);
#endif

