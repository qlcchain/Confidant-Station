/*************************************************************************
*
*  confidant 节点寻址头文件
*
* 
* 
* 
* 
*
* 
* 
* 
* 
*
* 
* 
*************************************************************************/
#ifndef CFD_ROUTE_HEADER
#define CFD_ROUTE_HEADER
#include "common_lib.h"
#include "pn_imserver.h"
#include "nTox.h"

#define CFD_USER_PUBKEYLEN 44 
#define CFD_RNODE_RID_UNKNOWN     0
#define CFD_RNODE_DEFAULT_RID     1
#define CFD_RNODE_DEFAULT_WEIGHT  0
#define CFD_RNODE_SERVER_WEIGHT  100
#define CFD_RNODE_SELF_WEIGHT    0xFF
#define CFD_RNODE_MAXNUM 255      //0xFF
#define CFD_NODEID_USERINDEX    0//主通信tox用户
#define CFD_ROUTEID_USERINDEX    PNR_IMUSER_MAXNUM//节点寻址routerid
#ifdef DEV_ONESPACE
#define CFD_URECORD_MAXNUM  4095// 0xFFF //单个节点上最多记录的用户个数
#else
#define CFD_URECORD_MAXNUM  65535// 0xFFFF //单个节点上最多记录的用户个数
#endif
#define CFD_RIDRECORD_MAXNUM  256 //单个节点上最多记录的节点数量
#define CFD_ACTIVERID_MAXNUM    10    //默认一个用户最多在十个节点上激活
#define CFD_IDLIST_MAXLEN  368 //最多一百个好友的id序列号
#define CFD_USERONE_INFOMAXLEN     256  
#define immsgForward        "immsgForward"
#define immsgForwardRes     "immsgForwardRes"
#define immsgNodeMsg        "NodeMsg"
#define immsgNodeMsgRly     "RNodeMsg"

//节点间传递消息类型
enum CFD_RNODEMSG_TYPE_ENUM
{
    CFD_RNODEMSG_TYPE_NONE = 0,
    CFD_RNODEMSG_TYPE_FORWARD = 1,
    CFD_RNODEMSG_TYPE_FORWARDRES = 2,
    CFD_RNODEMSG_TYPE_NODEMSG = 3,
    CFD_RNODEMSG_TYPE_NODEMSGRLY = 4,
    CFD_RNODEMSG_TYPE_BUTT,
};
//节点信息变更动作
enum CFD_RNODE_ACTION_ENUM
{
    CFD_RNODE_ACTION_NONE = 0,
    CFD_RNODE_ACTION_NEWNODE,
    CFD_RNODE_ACTION_MOVE,
    CFD_RNODE_ACTION_DELNODE,
    CFD_RNODE_ACTION_BUTT,
};
enum CFD_FRIENDINFO_ACTION_ENUM
{
    CFD_FRIENDINFO_ACTION_NONE = 0,
    CFD_FRIENDINFO_ACTION_NEWFRIEND,
    CFD_FRIENDINFO_ACTION_DELFRIEND,
    CFD_FRIENDINFO_ACTION_REMARK,
    CFD_FRIENDINFO_ACTION_BUTT,
};

enum CFD_GROUPINFO_ACTION_ENUM
{
    CFD_GROUPINFO_ACTION_NONE = 0,
    CFD_GROUPINFO_ACTION_NEWGROUP,
    CFD_GROUPINFO_ACTION_DELGROUP,
    CFD_GROUPINFO_ACTION_CHANGEGNAME,
    CFD_GROUPINFO_ACTION_ADDUSER,
    CFD_GROUPINFO_ACTION_DELUSER,
    CFD_GROUPINFO_ACTION_BUTT,
};
enum CFD_BAKFILE_RETURN_ENUM
{
    CFD_BAKFILE_RETURN_OK = 0,
    CFD_BAKFILE_RETURN_BADPARAMS =1,
    CFD_BAKFILE_RETURN_NOSPACE =2,
    CFD_BAKFILE_RETURN_FILENAMEREPEAT =3,
    CFD_BAKFILE_RETURN_NOPATH =4,
    CFD_BAKFILE_RETURN_ERROTHERS =5,
};
enum CFD_FILEACTION_RETURN_ENUM
{
    CFD_FILEACTION_RETURN_OK = 0,
    CFD_FILEACTION_RETURN_BADPARAMS =1,
    CFD_FILEACTION_RETURN_NOTARGET =2,
    CFD_FILEACTION_RETURN_FILENAMEREPEAT =3,
    CFD_FILEACTION_RETURN_NOSPACE =4,
    CFD_FILEACTION_RETURN_PATHNOTNULL =5,
    CFD_FILEACTION_RETURN_ERROTHERS,
};

enum CFD_CHANGELOG_TYPE_ENUM
{
    CFD_CHANGELOG_TYPE_NONE = 0,
    CFD_CHANGELOG_TYPE_USERINFO = 1,
    CFD_CHANGELOG_TYPE_USERFRIENDS = 2,
    CFD_CHANGELOG_TYPE_GROUPINFO = 3,
};
//用户好友记录，所以一组好友关系，实际上有两条记录
struct cfd_friends_record
{
    int id;
    int createtime;
    int status;//用户单方面设置状态
    int index;//用户在本地用户列表的index
    int uid;//这里对应着该用户在全局用户中的列表
    int fid;//好友在全局用户中的列表id
    int oneway;//单向好友标识
    char uidstr[CFD_USER_PUBKEYLEN+1];
    char fidstr[CFD_USER_PUBKEYLEN+1];
    char remark[PNR_USERNAME_MAXLEN+1];
};

//每个用户一个用户记录
struct cfd_uinfo_struct
{
    int id;//数据库id
    int local;
    int index;//本地用户index
    int uinfo_seq;//用户个人信息序列号，每次变更++
    int friend_seq;//用户好友信息序列号，每次变更++
    int friend_num;//用户好友数量
    int createtime;
    int version;//用户个人信息版本，默认从1开始
    int type;
    int capacity;
    char uidstr[CFD_USER_PUBKEYLEN+1];//用户账户，这里和用户公钥是同一个值
    char uname[PNR_USERNAME_MAXLEN+1];
    char mailinfo[EMAIL_USERS_CACHE_MAXLEN+1];
    char avatar[PNR_FILENAME_MAXLEN+1];
    char md5[PNR_MD5_VALUE_MAXLEN+1];
    char info[PNR_ATTACH_INFO_MAXLEN];
};
//用户活跃信息
struct cfd_useractive_struct
{
    int id;
    int active_time;
    int uindex;
    int status;
    int active_rid;
    //int last_rid;
    int rid_num;
    char uidstr[CFD_USER_PUBKEYLEN+1];
    char rid_liststr[PNR_USERNAME_MAXLEN+1];
    int ridlist[CFD_ACTIVERID_MAXNUM+1];
};
//项目全局统计信息
struct cfd_generinfo
{
    int total_user;
    int local_user;
    int active_user;
    int old_user;
    int other_user;
    int total_group;
    int local_group;
    int other_group;
    int rnode_num;
};
//每一次用户好友(群)信息变更记录一条
struct cfd_changelog_info
{
    int id;
    int timestamp;
    int type;
    int index;
    int seq;
    int action;
    int version;
    int src_rid;
    int dst_rid;
    char src_uid[CFD_USER_PUBKEYLEN+1];
    char dst_uid[CFD_USER_PUBKEYLEN+1];
    char info[PNR_ATTACH_INFO_MAXLEN+1];
};

enum CFD_RID_NODE_CSTATUS_ENUM
{
    CFD_RID_NODE_CSTATUS_NONE = 0,
    CFD_RID_NODE_CSTATUS_CONNETTING,
    CFD_RID_NODE_CSTATUS_CONNETTED,
    CFD_RID_NODE_CSTATUS_CONNETCLOSE,
    CFD_RID_NODE_CSTATUS_CONNETERR,
    CFD_RID_NODE_CSTATUS_BUTT
};

//confidant 节点信息
struct cfd_nodeinfo_struct
{
    int id;
    int type;
    int weight;
    int node_fid;
    int route_fid;
    int node_cstatus;//连接状态
    int route_cstatus;//连接状态
    char mac[MACSTR_MAX_LEN+1];
    char nodeid[TOX_ID_STR_LEN+1];
    char routeid[TOX_ID_STR_LEN+1];
    char rname[PNR_USERNAME_MAXLEN+1];
    char info[PNR_USERNAME_MAXLEN+1];
};
//rnodeget 响应
struct cfd_rnodeget_resp
{
    int ret;
    int num;
    struct cfd_nodeinfo_struct* pnodelist;
};

//rnodeonline user struct
struct cfd_rnodeonline_userone
{
    int id;
    int index;
    int lasttime;
    char uidstr[CFD_USER_PUBKEYLEN+1];
};

//旧数据的映射关系
struct cfd_olddata_mapping
{
    int id;
    int index;
    int nodeid;
    char idstr[CFD_USER_PUBKEYLEN+1];
    char toxid[TOX_ID_STR_LEN+1];
    char devid[TOX_ID_STR_LEN+1];
};
struct cfd_innode_users_info
{
    int uid;
    int index;
    int friend_seq;
    int uinfo_seq;
    int last_active;
    int active_rid;
    char idstr[CFD_USER_PUBKEYLEN+1];
};
struct cfd_node_online_msghead
{
    int type;
    int weight;
    int innode_usernum;
    char mac[MACSTR_MAX_LEN+1];
    char nodeid[TOX_ID_STR_LEN+1];
    char routeid[TOX_ID_STR_LEN+1];
    char rname[PNR_USERNAME_MAXLEN+1];
};
struct cfd_node_online_msgstruct
{
    int to_rid;
    struct cfd_node_online_msghead head;
    struct cfd_innode_users_info users[PNR_IMUSER_MAXNUM+1];
};
int get_uindexbyuid(char* p_uid);
int cfd_uinfolist_getidleid(void);
int cfd_rnodelist_getidleid(void);
int cfd_nodelist_getidleid(int node_flag,char* devid);
int cfd_rnodelist_getid_bydevid(int node_flag,char* devid);
int cfd_rnodelist_addnewnode(int uid,char* p_nodeid);
int cfd_filelist_init(void);
int cfd_userdata_init(void);
int cfd_uactive_newuser_dbinsert(struct cfd_useractive_struct *puser);
int cfd_oldusermapping_dbinsert(struct cfd_olddata_mapping *puser);
int cfd_uinfodbid_dbget_byindex(int uindex,int* db_id);
int cfd_rnode_userinfo_dbinsert(struct cfd_uinfo_struct *puser);
int cfd_rnodedb_init(void);
int sql_rnodedb_init(void);
int cfd_userdata_init(void);
int cfdsql_msglogdb_init(int index);
int cfd_dbfuzzygetid_bymailinfo(char* mailinfo,int* uid);
int cfd_olduseridstr_getbytoxid(char* p_toxid,char* p_idstr);
int cfd_olduseridstr_dbgetbytoxid(char* p_toxid,char* p_idstr);
int cfd_uinfo_dbupdate_byuid(struct cfd_uinfo_struct* puser);
int cfd_uinfomailinfo_dbupdate_byuid(int uid,int uinfoseq,char* mailinfo);
int cfd_uinfolistgetdbid_byuidstr(char* p_uidstr,int* p_uid);
int cfd_uinfolistgetindex_byuidstr(char* p_uidstr);
int cfd_uinfonode_addnew(int id,int index,int local,int type,int capacity,
        char* uidstr,char* pname,char* pmailinfo,char* pavatar,char* pmd5);
int cfd_friendsrecord_add(int index,char* puser,char* pfriend,char* remark);
int cfd_dbget_friendsall_byindex(int index);
int cfd_uactive_addnew(int id,int index,int active_rid,char* uidstr);
int cfd_uactive_dbupdate_byid(int id,int uindex,int active_rid,int lasttime,int node_num,char* ridlist);
int cfd_uactive_update_byidstr(struct cfd_innode_users_info* puser);
int cfd_rnode_self_detch(void);
int cfd_rnode_friend_connect(int node_flag);
int cfd_getindexbyidstr(char* p_id);
int cfd_toxidformatidstr(char* p_toxid,char* p_idstr);
int cfd_checklastactive_byuidstr(char* p_uidstr,int* p_index,int* p_rid);
int cfd_getfriendid_byidstr(int userid,char* friend_idstr);
int cfd_tox_send_message(Tox* ptox,int friend_num,char*pmsg,int msglen,int msgid);
int cfd_usersend_textmessage(int mlist_id,struct lws_cache_msg_struct * pmsg);
int cfd_usermsgnode_insert(int userid, char *from, char *to,char *pmsg, int msglen, int type, int logid, int msgid,char* sign, char* nonce, char* prikey);
int cfd_friendsrecord_delete(char* pfrom,char* pfriend,int oneway);
int cfd_rnodetox_msgnode_insert(char *from, char *to,int type,int msgid,int msglen,char *pmsg);
int cfd_nodeonline_notice_send(int rid);
int cfd_addfriend_devinfo_byidstr(int index,char* friend_uidstr);
int cfd_userlogin_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_group_pulllist_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_updata_avatar_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_userinfo_dbupdate_avatar(int index,char* avatr,char* md5);
int cfd_pullfriend_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_pullmsg_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_user_register_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_replaymsg_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_sendmsg_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_readmsg_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_pullfilepaths_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_pullfileslist_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_bakfile_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_fileaction_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
int cfd_nodeonline_notice_deal(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
#endif
