/*************************************************************************
*
*  pn im server 头文件
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
#ifndef PN_IM_SERVER_HEADER
#define PN_IM_SERVER_HEADER
  
#include "common_lib.h"
#include <libwebsockets.h>
#include "upload.h"
#include "nTox.h"

#define PNR_IM_SERVER_PORT		18006
#define PNR_IM_SERVER_PORT_BIN	18007

enum PNR_IM_CMDTYPE_ENUM
{
    PNR_IM_CMDTYPE_LOGIN = 0x01,
    PNR_IM_CMDTYPE_DESTORY,   
    PNR_IM_CMDTYPE_ADDFRIENDREQ ,   
    PNR_IM_CMDTYPE_ADDFRIENDPUSH ,   
    PNR_IM_CMDTYPE_ADDFRIENDDEAL ,   
    PNR_IM_CMDTYPE_ADDFRIENDREPLY ,   
    PNR_IM_CMDTYPE_DELFRIENDCMD ,   
    PNR_IM_CMDTYPE_DELFRIENDPUSH ,   
    PNR_IM_CMDTYPE_SENDMSG ,   
    PNR_IM_CMDTYPE_PUSHMSG ,   
    PNR_IM_CMDTYPE_READMSG ,   
    PNR_IM_CMDTYPE_READMSGPUSH ,   
    PNR_IM_CMDTYPE_DELMSG ,   
    PNR_IM_CMDTYPE_DELMSGPUSH ,   
    PNR_IM_CMDTYPE_HEARTBEAT ,
    PNR_IM_CMDTYPE_ONLINESTATUSCHECK ,
    PNR_IM_CMDTYPE_ONLINESTATUSPUSH ,
    PNR_IM_CMDTYPE_PULLMSG,
    PNR_IM_CMDTYPE_PULLFRIEND,
    PNR_IM_CMDTYPE_SENDFILE,
    PNR_IM_CMDTYPE_PUSHFILE,
    PNR_IM_CMDTYPE_PUSHFILE_TOX,
    PNR_IM_CMDTYPE_SYNCHDATAFILE,    
    PNR_IM_CMDTYPE_CREATENORMALUSER,// 24
    PNR_IM_CMDTYPE_LOGINIDENTIFY,
    PNR_IM_CMDTYPE_PREREGISTER,
    PNR_IM_CMDTYPE_REGISTER,
    PNR_IM_CMDTYPE_RECOVERYIDENTIFY,
    PNR_IM_CMDTYPE_RECOVERY,
    PNR_IM_CMDTYPE_PULLUSERLIST,
    PNR_IM_CMDTYPE_PULLFILE,
    PNR_IM_CMDTYPE_LOGOUT,
    PNR_IM_CMDTYPE_USERINFOUPDATE,
    PNR_IM_CMDTYPE_USERINFOPUSH,
    PNR_IM_CMDTYPE_CHANGEREMARKS,
    PNR_IM_CMDTYPE_GET_RELATIONSHIP,
    PNR_IM_CMDTYPE_PULLFILELIST,
    PNR_IM_CMDTYPE_UPLOADFILEREQ,
    PNR_IM_CMDTYPE_UPLOADFILE,
    PNR_IM_CMDTYPE_DELETEFILE,     
    PNR_IM_CMDTYPE_ROUTERLOGIN,
    PNR_IM_CMDTYPE_RESETROUTERKEY,
    PNR_IM_CMDTYPE_RESETUSERIDCODE,
    PNR_IM_CMDTYPE_GETDISKDETAILINFO,
    PNR_IM_CMDTYPE_GETDISKTOTALINFO,
    PNR_IM_CMDTYPE_FORMATDISK,
    PNR_IM_CMDTYPE_REBOOT,
    PNR_IM_CMDTYPE_BUTT ,   
};
enum PNR_IM_SYSCHDATAFILE_TYPEENUM
{
    PNR_IM_SYSCHDATAFILE_NONEED = 0,
    PNR_IM_SYSCHDATAFILE_UPLOAD,
    PNR_IM_SYSCHDATAFILE_DOWNLOAD,
    PNR_IM_SYSCHDATAFILE_BUTT
};
enum PNR_USER_LOGIN_RETCODE_ENUM
{
    PNR_USER_LOGIN_OK = 0,
    PNR_USER_LOGIN_BAD_ROUTERID,
    PNR_USER_LOGIN_NO_FREE_USER,
    PNR_USER_LOGIN_NO_SERVER,
    PNR_USER_LOGIN_OTHER_ERR,
    PNR_USER_LOGIN_BUTT,
};
enum PNR_USER_DESTORY_RETCODE_ENUM
{
    PNR_USER_DESTORY_OK = 0,
    PNR_USER_DESTORY_BAD_ROUTERID,
    PNR_USER_DESTORY_BAD_USERID,
    PNR_USER_DESTORY_OTHER_ERR,
    PNR_USER_DESTORY_BUTT,
};  
enum PNR_USER_ADDFRIEND_RETCODE_ENUM
{
    PNR_USER_ADDFRIEND_RETOK = 0,
    PNR_USER_ADDFRIEND_FAILED,
    PNR_USER_ADDFRIEND_FRIEND_EXSIT,
    PNR_USER_ADDFRIEND_BUTT,
};

enum PNR_MSGSEND_RETCODE_ENUM
{
    PNR_MSGSEND_RETCODE_OK = 0,
    PNR_MSGSEND_RETCODE_FAILED,
    PNR_MSGSEND_RETCODE_NOT_FRIEND,
};

enum PNR_DEBUGCMD_ENUM
{
    PNR_DEBUGCMD_SHOW_GLOBALINFO = 1,
    PNR_DEBUGCMD_DATAFILE_BASE64_CHANGED,
    PNR_DEBUGCMD_ACCOUNT_QRCODE_GET,
    PNR_DEBUGCMD_DEBUG_IMCMD,
    PNR_DEBUGCMD_PUSHNEWMSG_NOTICE,
    PNR_DEBUGCMD_SET_FUNCENABLE,
    PNR_DEBUGCMD_BUTT,
};
enum PNR_FUNCENABLE_ENUM
{
    PNR_FUNCENABLE_NOTICE_NEWMSG = 1,
    PNR_FUNCENABLE_BUTT,
};
enum PNR_FILESEND_RETCODE_ENUM
{
    PNR_FILESEND_RETCODE_OK = 0,
    PNR_FILESEND_RETCODE_NOFILE = 1,
    PNR_FILESEND_RETCODE_MD5 = 2,
    PNR_FILESEND_RETCODE_FAILED,  
};
enum PNR_USERINFOUPDATE_RETCODE_ENUM
{
    PNR_USERINFOUPDATE_RETCODE_OK = 0,
    PNR_USERINFOUPDATE_RETCODE_BADUID = 1,  
};

enum {
	PNR_FILE_OWNER_SELF = 1,
	PNR_FILE_OWNER_FRIEND = 2,
    PNR_FILE_OWNER_UPLOAD = 3,
};
enum PNR_APPACTIVE_STATUS_ENUM
{
    PNR_APPACTIVE_STATUS_FRONT = 0,
    PNR_APPACTIVE_STATUS_BACKEND = 1,
    PNR_APPACTIVE_STATUS_BUTT,
};
#define PNR_IMCMD_LOGIN       "Login"
#define PNR_IMCMD_DESTORY    "Destory"
#define PNR_IMCMD_ADDFRIEDNREQ "AddFriendReq"
#define PNR_IMCMD_ADDFRIENDPUSH  "AddFriendPush"
#define PNR_IMCMD_ADDREIENDDEAL  "AddFriendDeal"
#define PNR_IMCMD_ADDFRIENDREPLY  "AddFriendReply"
#define PNR_IMCMD_DELFRIENDCMD    "DelFriendCmd"
#define PNR_IMCMD_DELFRIENDPUSH   "DelFriendPush"
#define PNR_IMCMD_SENDMSG   "SendMsg"
#define PNR_IMCMD_PUSHMSG   "PushMsg"
#define PNR_IMCMD_SENDFILE	"SendFile"
#define PNR_IMCMD_SENDFILE_END	"SendFileEnd"
#define PNR_IMCMD_PUSHFILE	"PushFile"
#define PNR_IMCMD_PULLFILE	"PullFile"
#define PNR_IMCMD_PUSHFILE_TOX	"PushFileTox"
#define PNR_IMCMD_DELMSG   "DelMsg"
#define PNR_IMCMD_DELMSGPUSH   "PushDelMsg"
#define PNR_IMCMD_HEARTBEAT "HeartBeat"
#define PNR_IMCMD_ONLINESTATUSCHECK "OnlineStatusCheck"
#define PNR_IMCMD_ONLINESTATUSPUSH "OnlineStatusPush"
#define PNR_IMCMD_PULLMSG  "PullMsg"
#define PNR_IMCMD_PULLFRIEDN  "PullFriend"
#define PNR_IMCMD_SYNCHDATAFILE   "SynchDataFile"
#define PNR_IMCMD_NOT_FRIEND	"NotFriend"
//V2版本添加的命令
#define PNR_IMCMD_PREREGISTER       "PreRegister"
#define PNR_IMCMD_REGISTER       "Register"
#define PNR_IMCMD_LOGINIDENTIFY       "LoginIdentify"
#define PNR_IMCMD_RECOVERY       "Recovery"
#define PNR_IMCMD_RECOVERYIDENTIFY       "RecoveryIdentify"
#define PNR_IMCMD_PULLUSERLIST       "PullUserList"
#define PNR_IMCMD_CREATENORMALUSER       "CreateNormalUser"
#define PNR_IMCMD_READMSG             "ReadMsg"
#define PNR_IMCMD_READMSGPUSH             "ReadMsgPush"
#define PNR_IMCMD_LOGOUT              "LogOut"
#define PNR_IMCMD_USERINFOUPDATE        "UserInfoUpdate"
#define PNR_IMCMD_USERINFOPUSH        "UserInfoPush"
#define PNR_IMCMD_CHANGEREMARKS   "ChangeRemarks"
#define PNR_IMCMD_QUERYFRIEND		"QueryFriend"
#define PNR_IMCMD_LOGOUTPUSH		"PushLogout"
#define PNR_IMCMD_PULLFILELIST		"PullFileList"
#define PNR_IMCMD_UPLOADFILEREQ		"UploadFileReq"
#define PNR_IMCMD_UPLOADFILE		"UploadFile"
#define PNR_IMCMD_DELETEFILE		"DelFile"
#define PNR_IMCMD_ROUTERLOGIN        "RouterLogin"
#define PNR_IMCMD_RESETROUTERKEY        "ResetRouterKey"
#define PNR_IMCMD_RESETUSERIDCODE        "ResetUserIdcode"
#define PNR_IMCMD_GETDISKDETAILINFO        "GetDiskDetailInfo"
#define PNR_IMCMD_GETDISKTOTALINFO        "GetDiskTotalInfo"
#define PNR_IMCMD_FORMATDISK		"FormatDisk"
#define PNR_IMCMD_REBOOT			"Reboot"

#define PNR_IMCMD_PARAMS_KEYWORD_MAXLEN   32
#define PNR_IMCMD_PARAMS_VALUE_MAXLEN   128
#define PNR_IMCMD_PARAMS_URL_MAXLEN  256
#define PNR_IMCMD_PRARMS_MAXNUM       10
#define PNR_IMCMD_MSG_MAXLEN  2048
#define APPID_MAXLEN   32

#define PNR_IMCMD_PULLMSG_MAXNUM  20
#define PNR_API_VERSION_V1     1
#define PNR_API_VERSION_V2     2
#define PNR_API_VERSION_V3     3

#define SEG_CONTENT_LEN	(1024*1024*2)
#define MAX_FILE_BUFF	(1024*1024*3)
#define IM_MSG_MAGIC	0x0dadc0de

#ifdef DEV_ONESPACE
#define PNR_DB_USERFILE_HEAD     "/root"
#define DAEMON_PNR_TOP_DIR "/root/pnrouter/"
#define DAEMON_PNR_USERDATA_DIR   "/root/pnrouter/userdata/"
#define DAEMON_CONFIG_INI  "/root/pnrouter/pnrouter_conf.ini"
#define DB_TOP_FILE  "/root/pnrouter/pnrouter.db"
#define DB_FRIENDLIST_FILE  "/root/pnrouter/pnrouter_friends.db"
#define DB_MSGLOG_FILE  "/root/pnrouter/pnrouter_msglog.db"
#define DB_MSGCACHE_FILE "/root/pnrouter/pnrouter_msgcache.db"
#define PNR_ADMINUSER_QRCODEFILE  "/www/luci-static/resources/adminuser_qrcode.png"
#define PNR_P2PID_FILE  "/root/pnrouter/p2pid.txt"
#define PNR_DAEMON_TOX_DATAFILE "/root/pnrouter/data.ini"
#define PNR_DAEMON_TOX_DATABAKFILE "/root/pnrouter/data.ini_bak"
#define WS_SERVER_INDEX_FILETOPPATH  "/root/pnrouter/"
//#define WS_SERVER_INDEX_FILEPATH  "/root/pnrouter/mount-origin"
#define WS_SERVER_INDEX_FILEPATH	"/root/pnrouter/userdata"
#define WS_SERVER_SSLCERT_FILEPATH  "/root/pnrouter/mount-origin/localhost-100y.cert"
#define WS_SERVER_PRIVATEKEY_FILEPATH  "/root/pnrouter/mount-origin/localhost-100y.key"
#else
#define PNR_DB_USERFILE_HEAD     "/user"
#define DAEMON_PNR_TOP_DIR "/usr/pnrouter/"
#define DAEMON_PNR_USERDATA_DIR   "/usr/pnrouter/userdata/"
#define DAEMON_CONFIG_INI  "/usr/pnrouter/pnrouter_conf.ini"
#define DB_TOP_FILE  "/usr/pnrouter/pnrouter.db"
#define DB_FRIENDLIST_FILE  "/usr/pnrouter/pnrouter_friends.db"
#define DB_MSGLOG_FILE  "/usr/pnrouter/pnrouter_msglog.db"
#define DB_MSGCACHE_FILE "/usr/pnrouter/pnrouter_msgcache.db"
#define PNR_ADMINUSER_QRCODEFILE  "/www/luci-static/resources/adminuser_qrcode.png"
#define PNR_P2PID_FILE  "/usr/pnrouter/p2pid.txt"
#define PNR_DAEMON_TOX_DATAFILE "/usr/pnrouter/data.ini"
#define PNR_DAEMON_TOX_DATABAKFILE "/usr/pnrouter/data.ini_bak"
#define WS_SERVER_INDEX_FILETOPPATH  "/usr/pnrouter/"
//#define WS_SERVER_INDEX_FILEPATH  "/usr/pnrouter/mount-origin"
#define WS_SERVER_INDEX_FILEPATH	"/usr/pnrouter/userdata"
#define WS_SERVER_SSLCERT_FILEPATH  "/usr/pnrouter/mount-origin/localhost-100y.cert"
#define WS_SERVER_PRIVATEKEY_FILEPATH  "/usr/pnrouter/mount-origin/localhost-100y.key"
#endif

/* one of these is created for each client connecting to us */
struct per_session_data__minimal {
	struct per_session_data__minimal *pss_list;
	struct lws *wsi;
	uint32_t tail; /* the last message number we sent */
    int user_index;
	int fd;	/* sendfile fd */
	int sfile;
	int buflen;
	int type;
    int logid;
    char msgretbuf[IM_JSON_MAXLEN+1];
	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct lws_ring *ring; /* {lock_ring} ringbuffer holding unsent content */
};

struct per_session_data__minimal_bin {
	struct per_session_data__minimal_bin *pss_list;
	struct lws *wsi;
	uint32_t tail; /* the last message number we sent */
    int user_index;
	int fd;	/* sendfile fd */
	int sfile;
	int buflen;
	int type;
    int logid;
	char buf[MAX_FILE_BUFF];
    char msgretbuf[IM_JSON_MAXLEN+1];
	pthread_mutex_t lock_ring; /* serialize access to the ring buffer */
	struct lws_ring *ring; /* {lock_ring} ringbuffer holding unsent content */
};

struct imcmd_msghead_struct
{
    int im_cmdtype;
    int timestamp;
    int api_version;
    int iftox;
    int forward;
	int friendnum;
	int offset;
	double msgid;
    void *toxmsg;
    //int cmd;
    int no_parse_msgid;
    char appid[APPID_MAXLEN+1];
    int to_userid;
};
struct im_cmd_common_struct
{
    int im_cmdtype;
    int params_num;
    char param_key[PNR_IMCMD_PRARMS_MAXNUM][PNR_IMCMD_PARAMS_KEYWORD_MAXLEN+1];
    char param_value[PNR_IMCMD_PRARMS_MAXNUM][PNR_IMCMD_PARAMS_VALUE_MAXLEN+1];
    char im_url[PNR_IMCMD_PARAMS_URL_MAXLEN+1];
    char im_msg[PNR_IMCMD_MSG_MAXLEN+1];
};
struct tox_msg_struct
{
    struct list_head list;
    int msg_type;
    char fromuser_toxid[TOX_ID_STR_LEN+1];
    char touser_toxid[TOX_ID_STR_LEN+1];
    char msg_buff[IM_MSG_MAXLEN+1];
};
//libwebsocket消息体
struct lws_msg_struct
{
    struct list_head list;
    int index;
	int msgid;
    char user_id[TOX_ID_STR_LEN+1];
	void *msg_payload; /* is malloc'd */
	size_t msg_len;
};

enum {
    PNR_MSG_CACHE_TYPE_LWS,     //设备通过LWS发送消息到APP
    PNR_MSG_CACHE_TYPE_TOX,     //设备通过TOX发送消息到另外的设备
    PNR_MSG_CACHE_TYPE_TOXF,    //设备通过TOX发送文件到另外的设备
    PNR_MSG_CACHE_TYPE_TOXA,    //设备通过TOX发送消息到APP
    PNR_MSG_CACHE_TYPE_TOXAF,   //设备通过TOX发送文件到APP
};
enum{
    PNR_PUSHLOGOUT_REASON_RELOGIN = 1,
    PNR_PUSHLOGOUT_REASON_SYSTEM,
};
#define PNR_PUSHLOGOUT_RELOGIN_STRING  "relogin"
//缓存消息结构体
struct lws_cache_msg_struct
{
	struct list_head list;
    int notice_flag;
    int userid;
	int msgid;
	int msglen;
	int timestamp;
	int resend;
    int type;   //消息类型
    int ctype;  //cache类型  LWS TOX TOXF
    int ftype;  //文件类型
    int friendnum;
    int friendid;
    int filestatus; //文件发送状态 0:未发送  1:正在发送
    int filesize;
    int logid;
    char fromid[TOX_ID_STR_LEN+1];
    char toid[TOX_ID_STR_LEN+1];
    char filename[UPLOAD_FILENAME_MAXLEN];
    char filepath[UPLOAD_FILENAME_MAXLEN*2];
    char srckey[PNR_RSA_KEY_MAXLEN+1];
    char dstkey[PNR_RSA_KEY_MAXLEN+1];
    char sign[PNR_RSA_KEY_MAXLEN+1];
    char nonce[PNR_RSA_KEY_MAXLEN+1];
    char prikey[PNR_RSA_KEY_MAXLEN+1];
	char msg[0];
};

//tox消息体
struct imuser_toxmsg_struct
{
    struct list_head list;
    int usrid;
    int friendid;
    char data[IM_MSG_MAXLEN+1];
};

struct im_friends_struct
{
    int online_status;//用户在路由上在线状态
    int tox_onlinestatus;//tox好友的状态
    int tox_friendnum;
    int exsit_flag;
	int oneway;	//是否单向好友
	int sended;	//已发送
    unsigned int hashid;
	pthread_mutex_t lock_sended;
    char u_hashstr[PNR_USER_HASHID_MAXLEN+1];
    char user_nickname[PNR_USERNAME_MAXLEN+1];
    char user_remarks[PNR_USERNAME_MAXLEN+1];
    char user_toxid[TOX_ID_STR_LEN+1];
    char user_pubkey[PNR_USER_PUBKEY_MAXLEN+1];
};

struct im_friend_msgstruct
{
    int result;
    char fromuser_toxid[TOX_ID_STR_LEN+1];
    char touser_toxid[TOX_ID_STR_LEN+1];
    char nickname[PNR_USERNAME_MAXLEN+1];
    char friend_nickname[PNR_USERNAME_MAXLEN+1];
    char user_pubkey[PNR_USER_PUBKEY_MAXLEN+1];
    char friend_msg[PNR_FRIEND_MSG_MAXLEN+1];
};

enum IM_MSGTYPE_ENUM
{
	PNR_IM_MSGTYPE_TEXT = 0,
	PNR_IM_MSGTYPE_IMAGE = 1,
	PNR_IM_MSGTYPE_AUDIO = 2,
	PNR_IM_MSGTYPE_SYSTEM = 3,
	PNR_IM_MSGTYPE_MEDIA = 4,
	PNR_IM_MSGTYPE_FILE = 5,
	PNR_IM_MSGTYPE_CUSTOME = 6
};
#define PNR_IM_MSGTYPE_FILEALL   0xF0//包含IMAGE，AUDIO，MEDIA，FILE
#define PNR_IM_MSGTYPE_ALL   0xF1//包含IMAGE，AUDIO，MEDIA，FILE TEXT

struct im_sendmsg_msgstruct
{
    int db_id;
    int log_id;
    int msgtype;
    int ext2;
    int timestamp;
    int msg_status;
    char from_uid[PNR_USER_HASHID_MAXLEN+1];
    char to_uid[PNR_USER_HASHID_MAXLEN+1];
    char fromuser_toxid[TOX_ID_STR_LEN+1];
    char touser_toxid[TOX_ID_STR_LEN+1];
    char msg_buff[IM_MSG_MAXLEN+1];
	char ext[IM_MSG_MAXLEN+1];
    char msg_srckey[PNR_RSA_KEY_MAXLEN+1];
    char msg_dstkey[PNR_RSA_KEY_MAXLEN+1];
    char sign[PNR_RSA_KEY_MAXLEN+1];
    char nonce[PNR_RSA_KEY_MAXLEN+1];
    char prikey[PNR_RSA_KEY_MAXLEN+1];
};
enum USER_MSG_SENDER_NUM
{
    USER_MSG_SENDER_SELF = 0,
    USER_MSG_RECIVEVE_SELF  = 1,
};
enum MSG_STATUS_NUM
{
    MSG_STATUS_UNKNOWN = 0,
    MSG_STATUS_SENDOK  = 1,
    MSG_STATUS_READ_OK = 2,
};
enum USER_ONLINE_STATUS_ENUM
{
    USER_ONLINE_STATUS_OFFLINE = 0,
    USER_ONLINE_STATUS_ONLINE,
    USER_ONLINE_STATUS_HIDDEN,
    USER_ONLINE_STATUS_BUSY,
    USER_ONLINE_STATUS_BUTT
};
#define IMUSER_HEARTBEAT_OFFLINENUM   3   

enum USER_ONLINE_TYPE_ENUM {
    USER_ONLINE_TYPE_NONE,
    USER_ONLINE_TYPE_LWS,
    USER_ONLINE_TYPE_TOX
};

//每个im用户的结构体
struct im_user_struct
{
    int init_flag;//该是否已经实例化过
    int appactive_flag;//app 激活状态
    int user_index;
    int user_onlinestatus;//在线状态  USER_ONLINE_STATUS_ENUM
    int user_online_type;   //用户在线类型 USER_ONLINE_TYPE_ENUM
    int friendnum;//好友个数
    int heartbeat_count;
    int appid;
    int notice_flag;
    unsigned int hashid;
    unsigned int msglog_dbid;
    unsigned int cachelog_dbid;
    pthread_t tox_tid;
    pthread_mutex_t userlock;
    char u_hashstr[PNR_USER_HASHID_MAXLEN+1];
    char user_toxid[TOX_ID_STR_LEN+1];
    char user_name[PNR_USERNAME_MAXLEN+1];
    char user_nickname[PNR_USERNAME_MAXLEN+1];
    char userdata_pathurl[PNR_FILEPATH_MAXLEN];
    char userdata_fullurl[PNR_FILEPATH_MAXLEN];//全路径名称
    struct Tox* ptox_handle;
    struct per_session_data__minimal *pss;
    struct im_friends_struct friends[PNR_IMUSER_FRIENDS_MAXNUM+1];
	struct im_sendfile_struct file[PNR_MAX_SENDFILE_NUM];
};

struct im_user_array_struct
{
    int max_user_num;
    int cur_user_num;
    struct im_user_struct usrnode[PNR_IMUSER_MAXNUM+1];
};

//pnr 账号结构
struct pnr_account_struct
{
    int dbid;
    int index;
    int type;
    int active;
    int lastactive;
    char user_sn[PNR_USN_MAXLEN+1];
    char nickname[PNR_USERNAME_MAXLEN+1];
    char mnemonic[PNR_USERNAME_MAXLEN+1];
    char identifycode[PNR_IDCODE_MAXLEN+1];
    char loginkey[PNR_LOGINKEY_MAXLEN+1];
    char toxid[TOX_ID_STR_LEN+1];
};

struct pnr_tox_datafile_struct
{
    int dbid;
    int user_index;
    int data_version;
    char toxid[TOX_ID_STR_LEN+1];
    char datafile_md5[PNR_MD5_VALUE_MAXLEN+1];
    char datafile_curpath[PNR_FILEPATH_MAXLEN+1];
    char datafile_bakpath[PNR_FILEPATH_MAXLEN+1];
};
struct pnr_account_array_struct
{
    int normal_user_num;
    int temp_user_num;
    int admin_user_num;
    int total_user_num;
    char temp_user_sn[PNR_USN_MAXLEN+1];
    char temp_user_qrcode[PNR_QRCODE_MAXLEN+1];
    char defadmin_user_qrcode[PNR_QRCODE_MAXLEN+1];
    struct pnr_account_struct account[PNR_IMUSER_MAXNUM+1];
};

enum PNR_CREATE_NORMALUSER_RETCODE_ENUM
{
    PNR_CREATE_NORMALUSER_RETCODE_OK = 0,
    PNR_CREATE_NORMALUSER_RETCODE_BADRID,
    PNR_CREATE_NORMALUSER_RETCODE_BADUID,
    PNR_CREATE_NORMALUSER_RETCODE_NOMORE_USERS,
    PNR_CREATE_NORMALUSER_RETCODE_BUTT
};
enum PNR_LOGIN_RETCODE_ENUM
{
    PNR_LOGIN_RETCODE_OK = 0,
    PNR_LOGIN_RETCODE_NEED_IDENTIFY,
    PNR_LOGIN_RETCODE_BAD_RID,
    PNR_LOGIN_RETCODE_BAD_UID,
    PNR_LOGIN_RETCODE_BAD_LOGINKEY,
    PNR_LOGIN_RETCODE_BAD_IDCODE,
    PNR_LOGIN_RETCODE_OTHERS,
    PNR_LOGIN_RETCODE_BUTT
};
enum PNR_LOGINIDENTIFY_RETCODE_ENUM
{
    PNR_LOGINIDENTIFY_RETCODE_OK = 0,
    PNR_LOGINIDENTIFY_RETCODE_USER_ACTIVE,
    PNR_LOGINIDENTIFY_RETCODE_BAD_RID,
    PNR_LOGINIDENTIFY_RETCODE_BAD_USERTYPE,
    PNR_LOGINIDENTIFY_RETCODE_BAD_IDCODE,
    PNR_LOGINIDENTIFY_RETCODE_BAD_DATAFILE,
    PNR_LOGINIDENTIFY_RETCODE_OTHERS,
    PNR_LOGINIDENTIFY_RETCODE_BUTT
};

enum PNR_REGISTER_RETCODE_ENUM
{
    PNR_REGISTER_RETCODE_OK = 0,
    PNR_REGISTER_RETCODE_BADRID,
    PNR_REGISTER_RETCODE_USED,
    PNR_REGISTER_RETCODE_BAD_IDCODE,
    PNR_REGISTER_RETCODE_OTHERS,
    PNR_REGISTER_RETCODE_BUTT
};
enum PNR_RECOVERY_RETCODE_ENUM
{
    PNR_RECOVERY_RETCODE_USER_ACTIVED = 0,
    PNR_RECOVERY_RETCODE_USER_NOACTIVE,
    PNR_RECOVERY_RETCODE_BAD_RID,
    PNR_RECOVERY_RETCODE_TEMP_USER,
    PNR_RECOVERY_RETCODE_OTHERS_ERROR,
    PNR_RECOVERY_RETCODE_BUTT
};
enum PNR_RECOVERYIDENTIFY_RETCODE_ENUM
{
    PNR_RECOVERYIDENTIFY_RETCODE_OK = 0,
    PNR_RECOVERYIDENTIFY_RETCODE_BADRID,
    PNR_RECOVERYIDENTIFY_RETCODE_NO_ACTIVE,
    PNR_RECOVERYIDENTIFY_RETCODE_BAD_IDCODE,
    PNR_RECOVERYIDENTIFY_RETCODE_BAD_LOGINKEY,
    PNR_RECOVERYIDENTIFY_RETCODE_BUTT
};
enum PNR_PULLACCOUNTLIST_RETCODE_ENUM
{
    PNR_PULLACCOUNTLIST_RETCODE_OK = 0,
    PNR_PULLACCOUNTLIST_RETCODE_BAD_USERTYPE,
    PNR_PULLACCOUNTLIST_RETCODE_BAD_USERSN,
    PNR_PULLACCOUNTLIST_RETCODE_BUTT
};
enum PNR_LOGOUT_RETCODE_ENUM
{
    PNR_LOGOUT_RETCODE_OK = 0,
    PNR_LOGOUT_RETCODE_BADRID,
    PNR_LOGOUT_RETCODE_BADUID,
    PNR_LOGOUT_RETCODE_BUTT
};
enum PNR_CHANGEREMARKS_RETCODE_ENUM
{
    PNR_CHANGEREMARKS_RETCODE_OK = 0,
    PNR_CHANGEREMARKS_RETCODE_BADUID,
    PNR_CHANGEREMARKS_RETCODE_NOFRIEND,
    PNR_CHANGEREMARKS_RETCODE_BUTT
};
enum PNR_ROUTERLOGIN_RETCODE_ENUM
{
    PNR_ROUTERLOGIN_RETCODE_OK = 0,
    PNR_ROUTERLOGIN_RETCODE_BUSY = 1,
    PNR_ROUTERLOGIN_RETCODE_BADMAC = 2,
    PNR_ROUTERLOGIN_RETCODE_BADKEY = 3,
    PNR_ROUTERLOGIN_RETCODE_OTHERS,
    PNR_ROUTERLOGIN_RETCODE_BUTT
};
enum PNR_RESETLOGINKEY_RETCODE_ENUM
{
    PNR_RESETLOGINKEY_RETCODE_OK = 0,
    PNR_RESETLOGINKEY_RETCODE_BADRID = 1,
    PNR_RESETLOGINKEY_RETCODE_BADKEY = 2,
    PNR_RESETLOGINKEY_RETCODE_OTHERS,
    PNR_RESETLOGINKEY_RETCODE_BUTT
};
enum PNR_RESETIDCODE_RETCODE_ENUM
{
    PNR_RESETIDCODE_RETCODE_OK = 0,
    PNR_RESETIDCODE_RETCODE_BADRID = 1,
    PNR_RESETIDCODE_RETCODE_BADINPUT = 2,
    PNR_RESETIDCODE_RETCODE_BADIDCODE = 3,
    PNR_RESETIDCODE_RETCODE_OTHERS,
    PNR_RESETIDCODE_RETCODE_BUTT
};
struct im_user_msg_sendfile {
	uint32_t magic;
	uint32_t action;
	uint32_t segsize;
	uint32_t segseq;
	uint32_t offset;
	uint32_t fileid;
	uint16_t crc;
	uint8_t	segmore;
	uint8_t	ifcontinue;	//是否续传
	char filename[UPLOAD_FILENAME_MAXLEN];
	char fromid[TOX_ID_STR_LEN + 1];
	char toid[TOX_ID_STR_LEN + 1];
    char srckey[PNR_RSA_KEY_MAXLEN+1];
    char dstkey[PNR_RSA_KEY_MAXLEN+1];
	char content[SEG_CONTENT_LEN];
};

struct im_user_msg_sendfile_resp {
	uint32_t action;
	uint32_t fileid;
	uint32_t logid;
	uint32_t segseq;
	uint16_t crc;
	uint16_t code;	//返回码
	char fromid[TOX_ID_STR_LEN + 1];
	char toid[TOX_ID_STR_LEN + 1];
};
enum PNR_GLOBAL_SHOWINFO_TYPE
{
    PNR_GLOBAL_SHOWINFO_USERLIST = 0,
    PNR_GLOBAL_SHOWINFO_STATUS,
    PNR_SHOWINFO_CHECKUSER_BYTOXID,
    PNR_SHOWINFO_CHECKUSER_USERINDEX,
};

enum {
	PNR_FILE_ALL = 0,
	PNR_FILE_SEND = 1,
	PNR_FILE_RECV = 2,
	PNR_FILE_UPLOAD = 3
};
//推送消息结构体
struct newmsg_notice_params{
    int priority;
    int server_flag;
    int type;
    char from[TOX_ID_STR_LEN+1];
    char to[TOX_ID_STR_LEN+1];
    char title[PNR_USERNAME_MAXLEN+1];
    char payload[CMD_MAXLEN+1];
};
//磁盘统计信息
struct disk_total_info{
    int mode;
    int count;
    char used_capacity[MANU_NAME_MAXLEN+1];
    char total_capacity[MANU_NAME_MAXLEN+1];
};
//磁盘详细信息
struct dist_detail_info
{
    int slot;
    int status;
    int power_on;
    int temperature;
    char capacity[MANU_NAME_MAXLEN+1];
    char device[MANU_NAME_MAXLEN+1];
    char serial[MANU_NAME_MAXLEN+1];
    char name[MANU_NAME_MAXLEN+1];
    char firmware[MANU_NAME_MAXLEN+1];
    char formfactor[MANU_NAME_MAXLEN+1];
    char luwwndeviceid[MANU_NAME_MAXLEN+1];
    char sectorsizes[MANU_NAME_MAXLEN+1];
    char rotationrate[MANU_NAME_MAXLEN+1];
    char ataversion[MANU_NAME_MAXLEN+1];
    char sataversion[MANU_NAME_MAXLEN+1];
    char smartsupport[MANU_NAME_MAXLEN+1];
};
int im_server_main(void);
int im_server_init(void);
int im_rcvmsg_deal(struct per_session_data__minimal *pss, char* pmsg,
	int msg_len,char* retmsg,int* retmsg_len,int* ret_flag,int* plws_index);
int lws_send_onemsg(int id,struct lws *wsi,int* break_flag);
int imuser_friendstatus_push(int index,int online_status);
int imuser_heartbeat_deal(void);
int im_global_info_show(char* pcmd);
int get_indexbytoxid(char* p_toxid);
int pnr_datafile_base64decode(char* file_url,char* src_buff,int src_buflen);
int pnr_datafile_base64encode(char* file_url,char* encode_buff,int* encode_buflen);
int imtox_pushmsg_predeal(int id,char* puser,char* pmsg,int msg_len);
int im_datafile_base64_change_cmddeal(char* pcmd);
void im_send_msg_deal(int direction);
int pnr_create_account_qrcode(char* p_usn,char* p_ret,int* ret_len);
int im_account_qrcode_get_cmddeal(char* pcmd);
int adminaccount_qrcode_init(void);
int account_qrcode_show(char* p_sn);
int insert_lws_msgnode_ring(int id, char *pmsg, int msg_len);
int post_newmsg_notice(char* rid,char* targetid,char* msgpay,int server_flag);
int im_debug_setfunc_deal(char* pcmd);
int pnr_relogin_push(int index,int curtox_flag,int cur_fnum,struct per_session_data__minimal *cur_pss);
int pnr_encrypt_show(char* msg,int flag);
#endif
