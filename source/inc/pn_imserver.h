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
    PNR_IM_CMDTYPE_NONE = 0x0,
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
    PNR_IM_CMDTYPE_RESETROUTERNAME,
    PNR_IM_CMDTYPE_GETDISKDETAILINFO,
    PNR_IM_CMDTYPE_GETDISKTOTALINFO,
    PNR_IM_CMDTYPE_FORMATDISK,
    PNR_IM_CMDTYPE_REBOOT,
    PNR_IM_CMDTYPE_CREATEGROUP,
    PNR_IM_CMDTYPE_INVITEGROUP,
    PNR_IM_CMDTYPE_GROUPINVITEPUSH,
    PNR_IM_CMDTYPE_GROUPINVITEDEAL,
    PNR_IM_CMDTYPE_VERIFYGROUP,
    PNR_IM_CMDTYPE_VERIFYGROUPPUSH,
    PNR_IM_CMDTYPE_GROUPQUIT,
    PNR_IM_CMDTYPE_GROUPLISTPULL,
    PNR_IM_CMDTYPE_GROUPUSERPULL,
    PNR_IM_CMDTYPE_GROUPMSGPULL,
    PNR_IM_CMDTYPE_GROUPSENDMSG,
    PNR_IM_CMDTYPE_GROUPSENDFILEPRE,
    PNR_IM_CMDTYPE_GROUPSENDFILEDONE,
    PNR_IM_CMDTYPE_GROUPDELMSG,
    PNR_IM_CMDTYPE_GROUPMSGPUSH,
    PNR_IM_CMDTYPE_GROUPCONFIG,
    PNR_IM_CMDTYPE_GROUPSYSPUSH,
    PNR_IM_CMDTYPE_FILERENAME,
    PNR_IM_CMDTYPE_FILEFORWARD,
    PNR_IM_CMDTYPE_FILEFORWARD_PUSH,
    PNR_IM_CMDTYPE_UPLOADAVATAR,
    PNR_IM_CMDTYPE_UPDATEAVATAR,
    PNR_IM_CMDTYPE_PULLTMPACCOUNT,
    PNR_IM_CMDTYPE_DELUSER,
    PNR_IM_CMDTYPE_ENABLEQLCNODE,
    PNR_IM_CMDTYPE_CHECKQLCNODE,
    // 邮箱配置
    PNR_EM_CMDTYPE_SAVE_EMAILCOFIG,
    PNR_EM_CMDTYPE_PULL_EMAILCONFIG,
    PNR_EM_CMDTYPE_DEL_EMAILCONFIG,
    PNR_EM_CMDTYPE_SET_EMAILSIGN,
    PNR_EM_CMDTYPE_PULL_EMAILLIST,
    PNR_EM_CMDTYPE_BAKUPEMAIL,
    PNR_EM_CMDTYPE_DELEMAIL,
    PNR_EM_CMDTYPE_CHECKMAILUKEY,
    PNR_EM_CMDTYPE_GETBAKEMAILNUM,
    PNR_EM_CMDTYPE_CHECKBAKEMAIL,
    //用户磁盘限额配置
    PNR_IM_CMDTYPE_GETCAPACITY,
    PNR_IM_CMDTYPE_SETCAPACITY,
    //rid独有的消息
    PNR_IM_CMDTYPE_SYSDEBUGMSG,
    PNR_IM_CMDTYPE_USRDEBUGMSG,
    PNR_IM_CMDTYPE_SYSDERLYMSG,
    PNR_IM_CMDTYPE_BUTT ,   
};
enum PNR_SYSDEBUG_CMDTYPE_ENUM
{
    PNR_SYSDEBUG_CMDTYPE_CHECK_SYSINFO = 0x01,
    PNR_SYSDEBUG_CMDTYPE_CHECK_NETINFO = 0x02,
    PNR_SYSDEBUG_CMDTYPE_REFLUSH_DEVREG = 0x03,
    PNR_SYSDEBUG_CMDTYPE_POST_DEBUGINFO = 0x04,
    PNR_SYSDEBUG_CMDTYPE_ACTIVE_USER = 0x05,
    PNR_SYSDEBUG_CMDTYPE_CHECK_FRIENDS = 0x06,
    PNR_SYSDEBUG_CMDTYPE_CHECKANDADD_FRIENDS = 0x07,
    PNR_SYSDEBUG_CMDTYPE_BUTT,
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
    PNR_DEBUGCMD_SET_SIMULATION,        // 7 
    PNR_DEBUGCMD_DEVINFO_REG,
    PNR_DEBUGCMD_RNODE_MSGSEND,
    PNR_DEBUGCMD_BUTT,
};
enum PNR_FUNCENABLE_ENUM
{
    PNR_FUNCENABLE_NOTICE_NEWMSG = 1,
    PNR_FUNC_SET_LOGDEBUG_LEVER = 2,
    PNR_FUNC_SET_UDP_RECDEBUGFLAG = 3,
    PNR_FUNC_SET_MSGDEBUG_FLAG = 4,
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
    PNR_FILE_AVATAR = 4,
    PNR_FILE_GROUP = 5,
    PNR_FILE_GROUPRECV = 6,
    PNR_FILE_MAILBAKUP = 7,
};
//文件来源类型
enum PNR_FILE_SRCFROM_ENUM
{
    PNR_FILE_SRCFROM_MSGSEND = 1,
    PNR_FILE_SRCFROM_MSGRECV = 2,
    PNR_FILE_SRCFROM_SELFUPLOAD = 3,
    PNR_FILE_SRCFROM_AVATAR = 4,
    PNR_FILE_SRCFROM_GROUPSEND = 5,
    PNR_FILE_SRCFROM_GROUPRECV = 6,
    PNR_FILE_SRCFROM_MAILBAKUP = 7,
    PNR_FILE_SRCFROM_BUTT,
};
struct pnr_file_dbinfo_struct
{
    int id;
    int info_ver;
    int uid;
    int timestamp;
    int msgid;
    int filesize;
    int filetype;
    int srcfrom;
    char from[TOX_ID_STR_LEN+1];
    char to[TOX_ID_STR_LEN+1];
    char md5[PNR_MD5_VALUE_MAXLEN+1];
    char filename[PNR_FILENAME_MAXLEN+1];
    char filepath[PNR_FILEPATH_MAXLEN+1];
    char fileinfo[PNR_FILEINFO_MAXLEN+1];
    char srckey[PNR_RSA_KEY_MAXLEN+1];
    char dstkey[PNR_RSA_KEY_MAXLEN+1];
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
#define PNR_IMCMD_RESETROUTERNAME        "ResetRouterName"
#define PNR_IMCMD_RESETUSERIDCODE        "ResetUserIdcode"
#define PNR_IMCMD_GETDISKDETAILINFO        "GetDiskDetailInfo"
#define PNR_IMCMD_GETDISKTOTALINFO        "GetDiskTotalInfo"
#define PNR_IMCMD_FORMATDISK		"FormatDisk"
#define PNR_IMCMD_REBOOT			"Reboot"
#define PNR_IMCMD_CREATEGROUP       "CreateGroup"
#define PNR_IMCMD_INVITEGROUP       "InviteGroup"
#define PNR_IMCMD_GROUPINVITEPUSH       "GroupInvitePush"
#define PNR_IMCMD_GROUPINVITEDEAL       "GroupInviteDeal"
#define PNR_IMCMD_VERIFYGROUP       "GroupVerify"
#define PNR_IMCMD_VERIFYGROUPPUSH       "GroupVerifyPush"
#define PNR_IMCMD_GROUPQUIT       "GroupQuit"
#define PNR_IMCMD_GROUPLISTPULL       "GroupListPull"
#define PNR_IMCMD_GROUPUSERPULL       "GroupUserPull"
#define PNR_IMCMD_GROUPMSGPULL       "GroupMsgPull"
#define PNR_IMCMD_GROUPSENDMSG       "GroupSendMsg"
#define PNR_IMCMD_GROUPSENDFILEPRE       "GroupSendFilePre"
#define PNR_IMCMD_GROUPSENDFILEDONE       "GroupSendFileDone"
#define PNR_IMCMD_GROUPDELMSG       "GroupDelMsg"
#define PNR_IMCMD_GROUPMSGPUSH       "GroupMsgPush"
#define PNR_IMCMD_GROUPCONFIG       "GroupConfig"
#define PNR_IMCMD_GROUPSYSPUSH       "GroupSysPush"
#define PNR_IMCMD_FILERENAME       "FileRename"
#define PNR_IMCMD_FILEFORWARD       "FileForward"
#define PNR_IMCMD_UPLOADAVATAR       "UploadAvatar"
#define PNR_IMCMD_UPDATEAVATAR       "UpdateAvatar"
#define PNR_IMCMD_PULLTMPACCOUNT       "PullTmpAccount"
#define PNR_IMCMD_DELUSER   "DelUser"
#define PNR_IMCMD_ENABLEQLCNODE   "EnableQlcNode"
#define PNR_IMCMD_CHECKQLCNODE   "CheckQlcNode"
// 邮箱配置
#define PNR_EMCMD_SAVE_EMAILCOFIG "SaveEmailConf"
#define PNR_EMCMD_PULL_EMAILCONFIG "PullEmailConf"
#define PNR_EMCMD_DEL_EMAILCONFIG  "DelEmailConf"
#define PNR_EMCMD_SET_EMAILSIGN     "SetEmailSign"
#define PNR_EMCMD_PULL_EMAILLIST   "PullMailList"
#define PNR_EMCMD_BAKUPEMAIL    "BakupEmail"
#define PNR_EMCMD_DELEMAIL    "DelEmail"
#define PNR_EMCMD_CHECKMAILUKEY    "CheckmailUkey"
#define PNR_EMCMD_GETBAKMAILSNUM    "BakMailsNum"
#define PNR_EMCMD_CHCEKBAKMAILS    "BakMailsCheck"

//用户磁盘限额配置
#define PNR_IMCMD_GETCAPACITY "GetCapactiy"
#define PNR_IMCMD_SETCAPACITY "SetCapactiy"
//rid特有命令
#define PNR_IMCMD_SYSDEBUGCMD   "SysDebug"
#define PNR_IMCMD_USRDEBUGCMD   "UsrDebug"
#define PNR_IMCMD_SYSDERLYCMD   "SysDeRelay"

#define PNR_IMCMD_BUTT  "Butt"

#define PNR_CMDTYPE_MSG_REGISTER "register user : "
#define PNR_CMDTYPE_MSG_DESTROY "user destroy account byself"
#define PNR_CMDTYPE_MSG_DELACCOUNT "user del account owner"
#define PNR_CMDTYPE_EXT_SUCCESS "success"
#define PNR_CMDTYPE_EXT_FAILED "failed"

#define PNR_IMCMD_PARAMS_KEYWORD_MAXLEN   32
#define PNR_IMCMD_PARAMS_VALUE_MAXLEN   128
#define PNR_IMCMD_PARAMS_URL_MAXLEN  256
#define PNR_IMCMD_PRARMS_MAXNUM       10
#define PNR_IMCMD_MSG_MAXLEN  2048
#define APPID_MAXLEN   32
#define PNR_FILEINFO_ATTACH_FLAG  ','
#define PNR_IMCMD_PULLMSG_MAXNUM  20
#define PNR_API_VERSION_V1     1
#define PNR_API_VERSION_V2     2
#define PNR_API_VERSION_V3     3
#define PNR_API_VERSION_V4     4
#define PNR_API_VERSION_V5     5
#define PNR_API_VERSION_V6     6
#define PNR_API_VERSION_MAXNUM     PNR_API_VERSION_V6
#define SEG_CONTENT_LEN	(1024*1024*2)
#define MAX_FILE_BUFF	(1024*1024*3)
#define IM_MSG_MAGIC	0x0dadc0de
#define PNR_RETCODE_ERR_BADSIGN      0xE1
#define PNR_RETCODE_ERR_TIMEOUT      0xE2
#ifdef DEV_ONESPACE
#define PNR_DB_USERFILE_HEAD     "/media"
#define DAEMON_PNR_TOP_DIR "/media/pnrouter/"
#define DAEMON_PNR_USERDATA_DIR   "/media/pnrouter/userdata/"
#define DAEMON_PNR_USERINFO_DIR   "/media/pnrouter/userinfo/"
#define DAEMON_CONFIG_INI  "/media/pnrouter/pnrouter_conf.ini"
#define DB_TOP_FILE  "/media/pnrouter/pnrouter.db"
#define DB_FRIENDLIST_FILE  "/media/pnrouter/pnrouter_friends.db"
#define DB_GROUPINFO_FILE  "/media/pnrouter/pnrouter_group.db"
#define PNR_ADMINUSER_QRCODEFILE  "/www/luci-static/resources/adminuser_qrcode.png"
#define PNR_P2PID_FILE  "/media/pnrouter/p2pid.txt"
#define PNR_DAEMON_TOX_DATAFILE "/media/pnrouter/data.ini"
#define PNR_DAEMON_TOX_DATABAKFILE "/media/pnrouter/data.ini_bak"
#define WS_SERVER_INDEX_FILETOPPATH  "/media/pnrouter/"
#define PNR_GROUP_DATA_PATH  "gpdata/"
//#define WS_SERVER_INDEX_FILEPATH  "/media/pnrouter/mount-origin"
#define WS_SERVER_INDEX_FILEPATH	"/media/pnrouter/userdata"
#define WS_SERVER_SSLCERT_FILEPATH  "/media/pnrouter/localhost-100y.cert"
#define WS_SERVER_PRIVATEKEY_FILEPATH  "/media/pnrouter/localhost-100y.key"
#define PNR_AVATAR_DIR "avatar/"
#define PNR_FILECACHE_DIR "cache/"
#define PNR_AVATAR_FULLDIR "/media/pnrouter/userdata/avatar/"
#define PNR_FILECACHE_FULLDIR "/media/pnrouter/userdata/cache/"
#define PNR_SYSWARNING_LOG    "/media/pnrouter/syswarning.log"
#define PNR_EMAIL_DB       "/media/pnrouter/pnrouter_email.db"
#else
#define PNR_DB_USERFILE_HEAD     "/user"
#define DAEMON_PNR_TOP_DIR "/usr/pnrouter/"
#define DAEMON_PNR_USERDATA_DIR   "/usr/pnrouter/userdata/"
#define DAEMON_PNR_USERINFO_DIR   "/usr/pnrouter/userinfo/"
#define DAEMON_CONFIG_INI  "/usr/pnrouter/pnrouter_conf.ini"
#define DB_TOP_FILE  "/usr/pnrouter/pnrouter.db"
#define DB_FRIENDLIST_FILE  "/usr/pnrouter/pnrouter_friends.db"
#define DB_GROUPINFO_FILE  "/usr/pnrouter/pnrouter_group.db"
#define PNR_EMAIL_DB       "/usr/pnrouter/pnrouter_email.db"
#define PNR_ADMINUSER_QRCODEFILE  "/www/luci-static/resources/adminuser_qrcode.png"
#define PNR_P2PID_FILE  "/usr/pnrouter/p2pid.txt"
#define PNR_DAEMON_TOX_DATAFILE "/usr/pnrouter/data.ini"
#define PNR_DAEMON_TOX_DATABAKFILE "/usr/pnrouter/data.ini_bak"
#define WS_SERVER_INDEX_FILETOPPATH  "/usr/pnrouter/"
#define PNR_GROUP_DATA_PATH  "gpdata/"
//#define WS_SERVER_INDEX_FILEPATH  "/usr/pnrouter/mount-origin"
#define WS_SERVER_INDEX_FILEPATH	"/usr/pnrouter/userdata"
#define WS_SERVER_SSLCERT_FILEPATH  "/usr/pnrouter/localhost-100y.cert"
#define WS_SERVER_PRIVATEKEY_FILEPATH  "/usr/pnrouter/localhost-100y.key"
#define PNR_AVATAR_DIR "avatar/"
#define PNR_FILECACHE_DIR "cache/"
#define PNR_AVATAR_FULLDIR "/usr/pnrouter/userdata/avatar/"
#define PNR_FILECACHE_FULLDIR "/usr/pnrouter/userdata/cache/"
#define PNR_SYSWARNING_LOG    "/usr/pnrouter/syswarning.log"
#endif
enum PNR_DBFILE_INDEX_ENUM
{
    PNR_DBFILE_INDEX_GENERDB = 1,
    PNR_DBFILE_INDEX_FRIENDDB,
    PNR_DBFILE_INDEX_GROUPDB,
    PNR_DBFILE_INDEX_MSGLOGDB,
    PNR_DBFILE_INDEX_MSGCACHEDB,
    PNR_DBFILE_INDEX_BUTT,
};
enum PNR_DBTABLE_INDEX_ENUM
{
    PNR_DBTABLE_INDEX_GENERDB_GENERCONF = 1,
    PNR_DBTABLE_INDEX_GENERDB_USRACCOUNT,
    PNR_DBTABLE_INDEX_GENERDB_USRINFO,
    PNR_DBTABLE_INDEX_GENERDB_LOGCACHE,
    PNR_DBTABLE_INDEX_GENERDB_USRINSTANCE,
    PNR_DBTABLE_INDEX_GENERDB_TOXDATA,
    PNR_DBTABLE_INDEX_GENERDB_USRDEVMAP,
    PNR_DBTABLE_INDEX_FRIENDDB_FRIENDS,
    PNR_DBTABLE_INDEX_GROUPDB_GROUPLIST,
    PNR_DBTABLE_INDEX_GROUPDB_GROUPUSER,
    PNR_DBTABLE_INDEX_GROUPDB_GROUPOPENER,
    PNR_DBTABLE_INDEX_GROUPDB_GROUPMSG,
    PNR_DBTABLE_INDEX_GROUPDB_GROUPREADID,
    PNR_DBTABLE_INDEX_GROUPDB_GROUPUSRREMARK,
    PNR_DBTABLE_INDEX_USRMSGDB_MSGTBL,
    PNR_DBTABLE_INDEX_USRMSGDB_FILETBL,
    PNR_DBTABLE_INDEX_USRMSGCAHCEDB_MSGTBL,
    PNR_DBTABLE_INDEX_BUTT,
};
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
    long timestamp;
    int api_version;
    int iftox;
    int forward;
	int friendnum;
	int offset;
    int repeat_flag;
	long msgid;
    //int cmd;
    int no_parse_msgid;
    int to_userid;
    int debug_flag;
    void *toxmsg;
    struct per_session_data__minimal *pss;
    char appid[APPID_MAXLEN+1];
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
    PNR_PUSHLOGOUT_REASON_SYSTEM = 2,
    PNR_PUSHLOGOUT_REASON_DELUSER = 3,
};
#define PNR_PUSHLOGOUT_RELOGIN_STRING  "relogin"
#define PNR_PUSHLOGOUT_DELACCOUNT_STRING  "account delete"
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
    int local;//是否是本地好友
    unsigned int hashid;
    pthread_mutex_t lock_sended;
    char u_hashstr[PNR_USER_HASHID_MAXLEN+1];
    char user_nickname[PNR_USERNAME_MAXLEN+1];
    char user_remarks[PNR_USERNAME_MAXLEN+1];
    char user_toxid[TOX_ID_STR_LEN+1];
    char user_devid[TOX_ID_STR_LEN+1];
    char user_devname[PNR_USERNAME_MAXLEN+1];
    char user_pubkey[PNR_USER_PUBKEY_MAXLEN+1];
};
struct im_userdev_mapping_struct
{
    int id;
    int userindex;
    char user_toxid[TOX_ID_STR_LEN+1];
    char user_devid[TOX_ID_STR_LEN+1];
    char user_devname[PNR_USERNAME_MAXLEN+1];
};
//用户好友列表
struct pnr_usermapping_struct
{
    int user_num;
    struct im_userdev_mapping_struct user[PNR_IMUSER_MAXNUM+1];
};
struct im_friend_msgstruct
{
    int result;
    char fromuser_toxid[TOX_ID_STR_LEN+1];
    char touser_toxid[TOX_ID_STR_LEN+1];
    char nickname[PNR_USERNAME_MAXLEN+1];
    char friend_nickname[PNR_USERNAME_MAXLEN+1];
    char user_pubkey[PNR_USER_PUBKEY_MAXLEN+1];
    char sign[PNR_RSA_KEY_MAXLEN+1];
    char friend_msg[PNR_FRIEND_MSG_MAXLEN+1];
};
//群组功能相关接口
#define PNR_GROUP_MANAGER_MAXNUM 5
#define PNR_GROUP_USERKEY_MAXLEN 128
#define PNR_GROUP_EXTINFO_MAXLEN 1024
#define PNR_GROUP_USERMSG_MAXLEN 50000//1024
#define PNR_GROUP_EXTINFO_MAXNUM 10

//群用户结构
enum GROUP_USER_TYPE_ENUM
{
    GROUP_USER_OWNER=0,
    GROUP_USER_MANAGER= 0x01,
    GROUP_USER_NORMAL= 0x02,
    GROUP_USER_BUTT,
};
struct group_user
{
    int gindex;
    int userindex;
    int type;
    int last_msgid;//最后一次读取
    int init_msgid;//入群的时候群logid
    char username[PNR_USERNAME_MAXLEN+1];
    char user_remarks[PNR_USERNAME_MAXLEN+1];
    char group_remarks[PNR_USERNAME_MAXLEN+1];
    char toxid[TOX_ID_STR_LEN+1];
    char userkey[PNR_GROUP_USERKEY_MAXLEN+1];//用户群密钥
    char user_pubkey[PNR_GROUP_USERKEY_MAXLEN+1];//用户自己的公钥
};

struct group_info
{
    int id;
    int init_flag;
    int ownerid;
    int verify;
    int manager_num;
    int user_num;
    int last_msgid;
    char group_name[PNR_USERNAME_MAXLEN+1];
    char group_hid[TOX_ID_STR_LEN+1];
    char owner[TOX_ID_STR_LEN+1];
    char group_filepath[PNR_FILEPATH_MAXLEN+1];
    struct group_user user[PNR_GROUP_USER_MAXNUM+1];
};
//邀请入群信息
struct group_invite_info
{
    int msg_id;
    char groud_hid[TOX_ID_STR_LEN+1];
    char inviter[TOX_ID_STR_LEN+1];
    char user[TOX_ID_STR_LEN+1];
    char aduitor[TOX_ID_STR_LEN+1];
    char user_pubkey[PNR_GROUP_USERKEY_MAXLEN+1];
    char user_groupkey[PNR_GROUP_USERKEY_MAXLEN+1];
    char inviter_name[PNR_USERNAME_MAXLEN+1];
    char user_name[PNR_USERNAME_MAXLEN+1];
    char group_name[PNR_USERNAME_MAXLEN+1];
    char msg[PNR_GROUP_EXTINFO_MAXLEN+1];
};
struct gpuser_map_struct
{
    int uindex;
    char userid[TOX_ID_STR_LEN+1];
    char userkey[PNR_GROUP_USERKEY_MAXLEN+1];
};
struct gpuser_maplist
{
    int usernum;
    struct gpuser_map_struct gpuser[PNR_GROUP_EXTINFO_MAXNUM+1];
};
enum GROUP_OPER_ACTION_ENUM
{
    GROUP_OPER_ACTION_ADDUSER = 0,
    GROUP_OPER_ACTION_DELUSER,
    GROUP_OPER_ACTION_DISOLVE,
    GROUP_OPER_ACTION_GOWNERDEL,
};
//群用户消息结构
struct group_user_msg
{
    int gid;
    int msgid;
    int timestamp;
    int type;
    int from_uid;
    int to_uid;
    int attend_all;
    char from[TOX_ID_STR_LEN+1];
    char to[TOX_ID_STR_LEN+1];
    char to_key[PNR_GROUP_USERKEY_MAXLEN+1];
    char file_key[PNR_GROUP_USERKEY_MAXLEN+1];
    char group_name[PNR_GROUP_USERKEY_MAXLEN+1];
    char msgpay[PNR_GROUP_USERMSG_MAXLEN+1];
    char attend[PNR_GROUP_EXTINFO_MAXLEN+1];
    char ext1[PNR_GROUP_EXTINFO_MAXLEN+1];//ext1存储文件相对路径
    char ext2[PNR_GROUP_EXTINFO_MAXLEN+1];//ext2存储文件信息 格式为:  fid:fsize:md5:fileinfo
};
enum GROUP_SYSMSG_ENUM
{
    GROUP_SYSMSG_REMARK_GROUPNAME = 0x01,
    GROUP_SYSMSG_VERIFY_MODIFY = 0x02,
    GROUP_SYSMSG_DELMSG_BYSELF = 0x03,
    GROUP_SYSMSG_DELMSG_BYADMIN = 0x04,
    GROUP_SYSMSG_NEWUSER = 0xF1,    
    GROUP_SYSMSG_SELFOUT = 0xF2,
    GROUP_SYSMSG_KICKOFF = 0xF3,
    GROUP_SYSMSG_DISGROUP = 0xF4,
};
enum GROUP_CONFIG_CMDTYPE_ENUM
{
    GROUP_CONFIG_CMDTYPE_SET_GNAME = 0x01,
    GROUP_CONFIG_CMDTYPE_SET_VERIFY = 0x02,
    GROUP_CONFIG_CMDTYPE_KICKUSER = 0x03,
    GROUP_CONFIG_CMDTYPE_SET_GREMARK = 0xF1,
    GROUP_CONFIG_CMDTYPE_SET_USERREMARK = 0xF2,
    GROUP_CONFIG_CMDTYPE_SET_GNICKNAME = 0xF3,
};
enum GROUP_CONFIG_RETCODE_ENUM
{
    GROUP_CONFIG_RETCODE_OK = 0,
    GROUP_CONFIG_RETCODE_BADPARAMS,
    GROUP_CONFIG_RETCODE_NOPOWER,
    GROUP_CONFIG_RETCODE_OTHERERR
};
struct group_sys_msg
{
    int type;
    int msgid;
    int result;
    int from_uid;
    int to_uid;
    int gid;
    char group_hid[TOX_ID_STR_LEN+1];//操作者
    char from_user[TOX_ID_STR_LEN+1];//操作者
    char to_user[TOX_ID_STR_LEN+1];//被操作者
    char msgtargetuser[TOX_ID_STR_LEN+1];//消息接收方
    char msgpay[PNR_GROUP_USERMSG_MAXLEN+1];
};
struct group_fileinfo_struct
{
    int filesize;
    char fileid[PNR_FILEINFO_MAXLEN+1];
    char md5[PNR_MD5_VALUE_MAXLEN+1];
    char attach_info[PNR_FILEINFO_MAXLEN+1];
};
enum IM_MSGTYPE_ENUM
{
	PNR_IM_MSGTYPE_TEXT = 0,
	PNR_IM_MSGTYPE_IMAGE = 1,
	PNR_IM_MSGTYPE_AUDIO = 2,
	PNR_IM_MSGTYPE_SYSTEM = 3,
	PNR_IM_MSGTYPE_MEDIA = 4,
	PNR_IM_MSGTYPE_FILE = 5,
	PNR_IM_MSGTYPE_AVATAR = 6,
	PNR_IM_MSGTYPE_EMAILFILE = 7,
    PNR_IM_MSGTYPE_EMAILATTACH = 8
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
    char msg_buff[IM_MSG_PAYLOAD_MAXLEN+1];
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

enum PNR_TOX_STATUS_ENUM
{
    PNR_TOX_STATUS_NONE = 0,
    PNR_TOX_STATUS_RUNNING,
    PNR_TOX_STATUS_TRYTOEXIT,
    PNR_TOX_STATUS_EXITED,
};
#define IM_MSGID_CACHENUM 10
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
    int tox_status;
    unsigned int hashid;
    unsigned int msglog_dbid;
    unsigned int cachelog_dbid;
    unsigned int user_capacity;
    pthread_t tox_tid;
    int lastmsgid_index;
    long cache_msgid[IM_MSGID_CACHENUM];
    char u_hashstr[PNR_USER_HASHID_MAXLEN+1];
    char user_toxid[TOX_ID_STR_LEN+1];
    char user_name[PNR_USERNAME_MAXLEN+1];
    char user_nickname[PNR_USERNAME_MAXLEN+1];
    char user_pubkey[PNR_USER_PUBKEY_MAXLEN+1];
    char userdata_pathurl[PNR_FILEPATH_MAXLEN];
    char userinfo_pathurl[PNR_FILEPATH_MAXLEN];//用户账户信息相关目录
    char userinfo_fullurl[PNR_FILEPATH_MAXLEN];//用户data文件全路径名称
    struct Tox* ptox_handle;
    struct per_session_data__minimal *pss;
    struct im_friends_struct friends[PNR_IMUSER_FRIENDS_MAXNUM+1];
	struct im_sendfile_struct file[PNR_MAX_SENDFILE_NUM];
    //int groudnode[PNR_GROUP_MAXNUM+1];
};
#define USERINFO_MAXLEN 1024
struct pnr_userinfo_struct
{
    int id;
    int index;
    int local;
    char userid[TOX_ID_STR_LEN+1];
    char devid[TOX_ID_STR_LEN+1];
    char avatar[PNR_FILENAME_MAXLEN];
    char md5[PNR_MD5_VALUE_MAXLEN+1];
    char info[USERINFO_MAXLEN+1];
};
struct im_user_array_struct
{
    int max_user_num;
    int cur_user_num;
    unsigned int default_user_capacity;
    struct im_user_struct usrnode[PNR_IMUSER_MAXNUM+1];
};
enum PNR_ACCOUNT_STATUS_ENUM
{
    PNR_ACCOUNT_STATUS_NOREADY = 0,
    PNR_ACCOUNT_STATUS_ACTIVE = 1,
    PNR_ACCOUNT_STATUS_INVALID = 2,
    PNR_ACCOUNT_STATUS_BUTT
};
//pnr 账号结构
struct pnr_account_struct
{
    int dbid;
    int index;
    int type;
    int active;
    int lastactive;
    int createtime;
    unsigned int capacity;
    char user_sn[PNR_USN_MAXLEN+1];
    char nickname[PNR_USERNAME_MAXLEN+1];
    char mnemonic[PNR_USERNAME_MAXLEN+1];
    char identifycode[PNR_IDCODE_MAXLEN+1];
    char loginkey[PNR_LOGINKEY_MAXLEN+1];
    char toxid[TOX_ID_STR_LEN+1];
    char user_pubkey[PNR_USER_PUBKEY_MAXLEN+1];
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
    int admin_user_index;
    int normal_user_num;
    int temp_user_num;
    int admin_user_num;
    int total_user_num;
    char temp_user_sn[PNR_USN_MAXLEN+1];
    char temp_user_qrcode[PNR_QRCODE_MAXLEN+1];
    char defadmin_user_qrcode[PNR_QRCODE_MAXLEN+1];
    struct pnr_account_struct account[PNR_IMUSER_MAXNUM+1];
};
#define PNR_GROUPID_PREFIX    "group"
#define PNR_GROUPID_PREFIX_LEN 5
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
	PNR_LOGIN_RETCODE_USER_INVAILD,
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
    PNR_RECOVERY_RETCODE_QRCODE_USED,
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
enum PNR_RESETDEVNAME_RETCODE_ENUM
{
    PNR_RESETDEVNAME_RETCODE_OK = 0,
    PNR_RESETDEVNAME_RETCODE_BADRID = 1,
    PNR_RESETDEVNAME_RETCODE_BADUID = 2,
    PNR_RESETDEVNAME_RETCODE_OTHERS,
    PNR_RESETDEVNAME_RETCODE_BUTT
};
enum PNR_FILERENAME_RETCODE_ENUM
{
    PNR_FILERENAME_RETCODE_OK = 0,
    PNR_FILERENAME_RETCODE_BADUID = 1,
    PNR_FILERENAME_RETCODE_BADFILENAME =2,
    PNR_FILERENAME_RETCODE_RENEWFILEEXSIT =3,
    PNR_FILERENAME_RETCODE_BUTT
};
enum PNR_FILEFORWARD_RETCODE_ENUM
{
    PNR_FILEFORWARD_RETCODE_OK = 0,
    PNR_FILEFORWARD_RETCODE_BADUID = 1,
    PNR_FILEFORWARD_RETCODE_BADFILENAME =2,
    PNR_FILEFORWARD_RETCODE_TARGETNOTONLINE = 3,
    PNR_FILEFORWARD_RETCODE_BUTT
};
enum PNR_UPLOAD_AVATAR_RETCODE_ENUM
{
    PNR_UPLOAD_AVATAR_RETCODE_OK = 0,
    PNR_UPLOAD_AVATAR_RETCODE_BADUID = 1,
    PNR_UPLOAD_AVATAR_RETCODE_FILENAME_ERR =2,
    PNR_UPLOAD_AVATAR_RETCODE_NOCHANGE = 3,
    PNR_UPLOAD_AVATAR_RETCODE_BUTT
};
enum PNR_UPDATE_AVATAR_RETCODE_ENUM
{
    PNR_UPDATE_AVATAR_RETCODE_OK = 0,
    PNR_UPDATE_AVATAR_RETCODE_BADUID = 1,
    PNR_UPDATE_AVATAR_RETCODE_NOCHANGE = 2,
    PNR_UPDATE_AVATAR_RETCODE_FILE_NOEXSIT =3,
    PNR_UPDATE_AVATAR_RETCODE_BUTT
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
enum PNR_CREATEGROUP_RETCODE_ENUM
{
    PNR_CREATEGROUP_RETCODE_OK = 0,
    PNR_CREATEGROUP_RETCODE_BADUID = 1,
    PNR_CREATEGROUP_RETCODE_BADPARAMS,
    PNR_CREATEGROUP_RETCODE_GROUPOVER,
    PNR_CREATEGROUP_RETCODE_BUTT
};
enum PNR_GROUPINVITE_RETCODE_ENUM
{
    PNR_GROUPINVITE_RETCODE_OK = 0,
    PNR_GROUPINVITE_RETCODE_BADUID,
    PNR_GROUPINVITE_RETCODE_BADPARAMS,
    PNR_GROUPINVITE_RETCODE_GROUPOVER,
    PNR_GROUPINVITE_RETCODE_BUTT
};
enum PNR_GROUPVERIFY_RETCODE_ENUM
{
    PNR_GROUPVERIFY_RETCODE_OK = 0,
    PNR_GROUPVERIFY_RETCODE_BADGID,
    PNR_GROUPVERIFY_RETCODE_BADUID,
    PNR_GROUPVERIFY_RETCODE_BADPARAMS,
    PNR_GROUPVERIFY_RETCODE_BUTT
};
enum PNR_GROUPQUIT_RETCODE_ENUM
{
    PNR_GROUPQUIT_RETCODE_OK = 0,
    PNR_GROUPQUIT_RETCODE_BADPARAMS,
    PNR_GROUPQUIT_RETCODE_NONEED_QUIT,
    PNR_GROUPQUIT_RETCODE_BUTT
};
enum PNR_GROUPPULL_RETCODE_ENUM
{
    PNR_GROUPPULL_RETCODE_OK = 0,
    PNR_GROUPPULL_RETCODE_ERR,
    PNR_GROUPPULL_RETCODE_BUTT
};
enum PNR_GROUPPULL_MSGTYPE_ENUM
{
    PNR_GROUPPULL_MSGTYPE_ALL = 0,
    PNR_GROUPPULL_MSGTYPE_TEXT = 1,
    PNR_GROUPPULL_MSGTYPE_FILE,
    PNR_GROUPPULL_MSGTYPE_BUTT
};
enum PNR_GROUPSENDMSG_RETCODE_ENUM
{
    PNR_GROUPSENDMSG_RETCODE_OK = 0,
    PNR_GROUPSENDMSG_RETCODE_BADPARAMS,
    PNR_GROUPSENDMSG_RETCODE_BADUSER,
    PNR_GROUPSENDMSG_RETCODE_BUTT
};
enum PNR_GROUP_MSGPUSH_ATTEND_ENUM
{
    PNR_GROUP_MSGPUSH_ATTEND_NONE = 0,
    PNR_GROUP_MSGPUSH_ATTEND_ALL,
    PNR_GROUP_MSGPUSH_ATTEND_ONLY
};
enum PNR_GROUP_DELMSG_TYPE_ENUM
{
    PNR_GROUP_DELMSG_TYPE_SELF = 0,
    PNR_GROUP_DELMSG_TYPE_ADMIN,
};
enum PNR_GROUP_DELMSG_RETURN_ENUM
{
    PNR_GROUP_DELMSG_RETURN_OK = 0,
    PNR_GROUP_DELMSG_RETURN_BADPRARMS,
    PNR_GROUP_DELMSG_RETURN_NOPOWER,
    PNR_GROUP_DELMSG_RETURN_BUTT
};
enum PNR_GROUP_SENDFILE_RETURN_ENUM
{
    PNR_GROUP_SENDFILE_RETURN_OK,
    PNR_GROUP_SENDFILE_RETURN_BADPRARMS,
    PNR_GROUP_SENDFILE_RETURN_BADMD5,  
    PNR_GROUP_SENDFILE_RETURN_BUTT,
};
enum PNR_ACCOUNT_DELETE_RETURN_ENUM
{
    PNR_ACCOUNT_DELETE_RETURN_OK,
    PNR_ACCOUNT_DELETE_RETURN_NOOWNER,
    PNR_ACCOUNT_DELETE_RETURN_BADUSER,  
    PNR_ACCOUNT_DELETE_RETURN_BUTT,
};
enum PNR_REBOOT_RETURN_ENUM
{
    PNR_REBOOT_RETURN_OK,
    PNR_REBOOT_RETURN_NOOWNER,
    PNR_REBOOT_RETURN_OTHERERR,
    PNR_REBOOT_RETURN_BUTT,
};
enum PNR_SAVEMAIL_RETURN_ENUM
{
    PNR_SAVEMAIL_RET_OK,
    PNR_SAVEMAIL_RET_REPEAT,
    PNR_SAVEMAIL_RET_OTHERERR,
    PNR_SAVEMAIL_RET_BUTT
};
#define WS_SENDFILE_HEADLEN    952
#define WS_FILELIST_V1  1 //这个版本新增的ver字段，添加了节点上文件保存真实名称与用户看见的逻辑名称区分
#define WS_FILELIST_VERSION WS_FILELIST_V1
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
    char porperty_flag;//是否是群会话属性
    char ver_str;//文件传输版本号
	char content[SEG_CONTENT_LEN];
};
#define PNR_REAL_FILENAME_GET(filename,uid,srcfrom,fid)\
{\
    snprintf(filename,PNR_FILENAME_MAXLEN,"U%03dS%02dF%u",uid,srcfrom,fid);\
}
#define PNR_REAL_FILEPATH_GET(filepath,uid,srcfrom,fid,gid,filename)\
{\
    switch(srcfrom)\
    {\
        case PNR_FILE_SRCFROM_MSGSEND:\
            snprintf(filepath,PNR_FILEPATH_MAXLEN,"/user%d/s/U%03dS%02dF%u",uid,uid,srcfrom,fid);\
            break;\
        case PNR_FILE_SRCFROM_MSGRECV:\
            snprintf(filepath,PNR_FILEPATH_MAXLEN,"/user%d/r/U%03dS%02dF%u",uid,uid,srcfrom,fid);\
            break;\
        case PNR_FILE_SRCFROM_SELFUPLOAD:\
            snprintf(filepath,PNR_FILEPATH_MAXLEN,"/user%d/u/U%03dS%02dF%u",uid,uid,srcfrom,fid);\
            break;\
        case PNR_FILE_SRCFROM_AVATAR:\
            snprintf(filepath,PNR_FILEPATH_MAXLEN,"/%s%s",PNR_FILECACHE_DIR,filename);\
            break;\
        case PNR_FILE_SRCFROM_GROUPSEND:\
        case PNR_FILE_SRCFROM_GROUPRECV:\
            snprintf(filepath,PNR_FILEPATH_MAXLEN,"/%sg%d/U%03dS%02dF%u",PNR_GROUP_DATA_PATH,gid,uid,PNR_FILE_SRCFROM_GROUPSEND,fid);\
            break;\
        case PNR_FILE_SRCFROM_MAILBAKUP:\
            snprintf(filepath,PNR_FILEPATH_MAXLEN,"/user%d/mail/U%03dS%02dF%u",uid,uid,srcfrom,fid);\
            break;\
        default:\
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"bad srcfrom(%d)",srcfrom);\
            break;\
    }\
}

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

#define PAPUSHMSG_DEVELOP_HTTPS_SERVER   "47.96.76.184"  //"192.168.137.64"
#define PAPUSHMSG_PRODUCT_HTTPS_SERVER   "pprouter.online"
#define PAPUSHMSG_HTTPSSERVER_PORT   9001
#define PAPUSHMSG_HTTPSSERVER_PREURL "/v1/pareg/pushmsg"
#define PAPUSHMSGS_HTTPSSERVER_PREURL "/v1/pareg/pushmsgs"
#define PNR_HTTPSSERVER_DEVREGISTER "/v1/pprmap/devreg"
#define PNR_HTTPSSERVER_DEVRWARN "/v1/pprmap/devwarn"
enum PUSHMSG_PRI_LEVER
{
    PUSHMSG_PRI_LEVER_LOW = 1,
    PUSHMSG_PRI_LEVER_MIDDLE = 2,
    PUSHMSG_PRI_LEVER_HIGH = 3,
};
enum PUSHMSG_TYPE_ENUM
{
    PUSHMSG_TYPE_DEBUGINFO = 0,
    PUSHMSG_TYPE_NOTICE_NEWMSG = 1,
    PUSHMSG_TYPE_SYSTEMINFO = 2,
    PUSHMSG_TYPE_CRETICALINFO = 3,
};
#define PNR_POSTMSG_TITLE "Confidant"
#define PNR_POSTMSG_PAYLOAD  "You Have new Messages"
#define PNR_POST_USER_MAXNUM 100
#define PNR_POST_USERSTR_MAXLEN  10000
#define PNR_POST_MSGS_VER1  1
//推送消息结构体
struct newmsg_notice_params{
    int priority;
    int server_flag;
    int type;
    int devid;
    int msgid;
    char from[TOX_ID_STR_LEN+1];
    char to[TOX_ID_STR_LEN+1];
    char title[PNR_USERNAME_MAXLEN+1];
    char dev[PNR_USERNAME_MAXLEN+1];
    char payload[CMD_MAXLEN+1];
};
//批量推送消息结构体
struct newmsgs_notice_params{
    int priority;
    int server_flag;
    int type;
    int to_num;
    int version;
    char from[TOX_ID_STR_LEN+1];
    char title[PNR_USERNAME_MAXLEN+1];
    char dev[PNR_USERNAME_MAXLEN+1];
    char tos[PNR_POST_USERSTR_MAXLEN+1];
    char payload[CMD_MAXLEN+1];
};

//磁盘统计信息
struct disk_total_info{
    int mode;
    int count;
    int errnum;
    int used_percent;
    char used_capacity[MANU_NAME_MAXLEN+1];
    char total_capacity[MANU_NAME_MAXLEN+1];
};
enum PNR_DISK_STATUS_ENUM
{
    PNR_DISK_STATUS_NONE = 0,//未挂载硬盘
    PNR_DISK_STATUS_NOINIT = 1,//挂载未初始化
    PNR_DISK_STATUS_RUNNING = 2,//正常使用中
    PNR_DISK_STATUS_ERROR = 3,//磁盘故障
};
enum PNR_DISK_MODE_ENUM
{
    PNR_DISK_MODE_NONE = 0,
    PNR_DISK_MODE_BASIC,
    PNR_DISK_MODE_RAID1,
    PNR_DISK_MODE_RAID0,
    PNR_DISK_MODE_BUTT
};
//磁盘详细信息
struct dist_detail_info
{
    int slot;
    int status;
    int power_on;
    int temperature;
    char modelfamily[MANU_NAME_MAXLEN+1];
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
enum PNR_RNODEMSG_RETCODE_ENUM
{
    PNR_RNODEMSG_RETCODE_OK = 0,
    PNR_RNODEMSG_RETCODE_BADRID,
    PNR_RNODEMSG_RETCODE_BADPARAMS,
    PNR_RNODEMSG_RETCODE_OTHERERR,
    PNR_RNODEMSG_RETCODE_BUTT
};

enum PNR_RID_NODE_CSTATUS_ENUM
{
    PNR_RID_NODE_CSTATUS_NONE = 0,
    PNR_RID_NODE_CSTATUS_CONNETTING,
    PNR_RID_NODE_CSTATUS_CONNETTED,
    PNR_RID_NODE_CSTATUS_CONNETCLOSE,
    PNR_RID_NODE_CSTATUS_CONNETERR,
    PNR_RID_NODE_CSTATUS_BUTT
};

//ppr根节点连接信息
struct pnr_rid_node
{
    int f_id;
    int c_status;//连接状态
    int c_type; // 连接类型
    time_t  lastact_time;
    struct Tox* ptox_handle;
    char tox_id[TOX_ID_STR_LEN+1];
    char node_name[PNR_USERNAME_MAXLEN+1];
};
#define  PNR_NETSTAT_RECQMAXNUM      50000
#define  PNR_SYSSOURCE_TMPBUFF_MAXNUM      90
#define  PNR_SYSSOURCE_CPUINFO_MAXNUM      90
#define PNR_NETSTAT_ERRPROCESS_RNGD        "rngd"
#define PNR_NETSTAT_ERRPROCESS_PNRSERVER        "pnr_server"
#define PNR_NETSTAT_ERRPROCESS_FRPC        "frpc"
enum PNR_MONITORINFO_ERRNUM
{
    PNR_MONITORINFO_ENUM_OK = 0,
    PNR_MONITORINFO_ENUM_NETSTATERR = 1,
    PNR_MONITORINFO_ENUM_TMPOVER = 2,
    PNR_MONITORINFO_ENUM_CPUOVER = 3,
    PNR_MONITORINFO_ENUM_DISKFORMAT = 4,
    PNR_MONITORINFO_ENUM_SYSREBOOT = 5,
    PNR_MONITORINFO_ENUM_BUTT
};
struct pnr_monitor_errinfo
{
    int err_no;
    int dev_num;
    int mode_num;
    char tox_id[TOX_ID_STR_LEN+1];
    char mac[MACSTR_MAX_LEN+1];
    char err_info[PNR_ATTACH_INFO_MAXLEN+1];
    char repair_info[PNR_ATTACH_INFO_MAXLEN+1];
};
#define PERUSER_TOXMSG_CACHENUM  30
enum TOX_CACHE_STATUS_ENUM
{
    TOX_CACHE_STATUS_NONE = 0,
    TOX_CACHE_STATUS_USED = 1,
    TOX_CACHE_STATUS_OVER = 2,
};
struct tox_msg_cache
{
    int used_flag;
    int f_num;
    int msgid;
    int reclen;
    char msg_buff[IM_JSON_MAXLEN+1];
};
typedef int ppr_cmddeal_cb(cJSON * params,char* retmsg,int* retmsg_len,int* plws_index, struct imcmd_msghead_struct *head);
struct ppr_func_struct
{
    int cmd;
    int api_version;
    int need_reply;
    ppr_cmddeal_cb* p_cmddeal_cb;
};
enum PNR_QLCNODE_ENABLE_ENUM
{
    PNR_QLCNODE_ENABLE_OK = 0,
    PNR_QLCNODE_ENABLE_NOSOURCE = 1,
    PNR_QLCNODE_ENABLE_NOLIMIT =2,
};
#define USER_CAPACITY_MIN_VALUE_GIGA    1 //最小磁盘配置限额1G
#define USER_CAPACITY_MAX_VALUE_GIGA    1024000//1024*1000，磁盘配额限制最大1000T
#define USER_CAPACITY_DEFAULT_VALUE_GIGA 20480//20T,20*1024
enum PNR_USER_CAPACITY_CONFIG_ENUM
{
    PNR_USER_CAPACITY_CONFIG_OK = 0,
    PNR_USER_CAPACITY_CONFIG_NOPOWER = 1,
    PNR_USER_CAPACITY_CONFIG_BADUSER =2,
    PNR_USER_CAPACITY_CONFIG_BADVALUE =3,
    PNR_USER_CAPACITY_CONFIG_OTHERS =4,
    PNR_USER_CAPACITY_CONFIG_BUTT,
};

// 邮箱帐号信息结构体
#define EMAIL_NAME_LEN  50
#define EMAIL_SIGN_LEN  100
#define EMAIL_CONFIG_LEN  300
#define EMAIL_INFO_MAXLEN 4096
#define EMAIL_UKEY_MAXNUM 30
#define EMAIL_USERS_CACHE_MAXLEN 1500
#define EMAIL_CONFIG_MAXNUM 20
#define EM_CACHE_SEPARATION_CHAR ','
#define EM_LISTPULL_DEFNUM    10
struct em_user_pkey_mapping
{
    int usernum;
    int pkeynum;
    char user_aray[EMAIL_UKEY_MAXNUM][EMAIL_NAME_LEN+1];
    char pkey_aray[EMAIL_UKEY_MAXNUM][PNR_USER_PUBKEY_MAXLEN+1];
};
enum EM_CHECKUKEY_RETCODE
{
    EM_CHECKUKEY_RET_OK = 0,
    EM_CHECKUKEY_RET_BADPARAMS,
    EM_CHECKUKEY_RET_NOTFOUND,
    EM_CHECKUKEY_RET_BUTT
};
enum EM_CONFIG_SET_RETCODE
{
    EM_CONFIG_SET_RET_OK = 0,
    EM_CONFIG_SET_RET_OVER,
    EM_CONFIG_SET_RET_REPEAT,
    EM_CONFIG_SET_RET_OTHERS,
    EM_CONFIG_SET_RET_BUTT
};
enum EM_BAKMAILSNUM_GET_RETCODE
{
    EM_BAKMAILSNUM_GET_RET_OK = 0,
    EM_BAKMAILSNUM_GET_RET_BADPARAMS,
    EM_BAKMAILSNUM_GET_RET_NOFOUND,
    EM_BAKMAILSNUM_GET_RET_NOPRIM,
    EM_BAKMAILSNUM_GET_RET_BUTT
};
enum EMAIL_TYPE_ENUM
{
    EMAIL_TYPE_QQ_ENTERPRISE = 1,
    EMAIL_TYPE_QQ_PERSON,
    EMAIL_TYPE_163_PERON,
    EMAIL_TYPE_GMAIL,
    EMAIL_TYPE_HOTMAIL,
    EMAIL_TYPE_ICLOUD,
    EMAIL_TYPE_OTHERS = 0xFF,
    EMAIL_TYPE_BUTT
};
struct email_config_mode
{
    int g_version;
    int g_type;
    char g_name[EMAIL_NAME_LEN+1];
    char g_config[EMAIL_CONFIG_LEN+1];
    char g_userkey[PNR_USER_PUBKEY_MAXLEN+1];
    char g_sign[EMAIL_SIGN_LEN+1];
    char g_contacts_file[EMAIL_SIGN_LEN+1];
    char g_contacts_md5[EMAIL_SIGN_LEN+1];
};
// 邮件信息结构体
struct email_model
{
    int e_mailid;
    int e_uid;
    int e_lable;
    int e_read;
    int e_box;
    int e_type;
    uint32_t e_fileid;
    char e_uuid[VERSION_MAXLEN+1];
    char e_userkey[PNR_USER_PUBKEY_MAXLEN+1];
    char e_mailinfo[EMAIL_INFO_MAXLEN+1];
    char e_emailpath[PNR_FILEPATH_MAXLEN+1];
    char e_user[EMAIL_NAME_LEN+1];
};
// 邮件节点信息结构体
// struct email_node_model
// {
//     int e_type;
//     char e_name[EMAIL_NAME_LEN+1];
//     char e_from[EMAIL_NAME_LEN+1];
//     char e_to[EMAIL_NAME_LEN+1];
//     char e_cc[EMAIL_NAME_LEN+1];
//     char e_userkey[PNR_USER_PUBKEY_MAXLEN+1];
//     char e_subject[EMAIL_SUBJECT_LEN+1];
//     char e_attachinfo[EMAIL_SUBJECT_LEN+1];
//     char e_emailpath[PATH_MAX+1];
//     char e_attach_name[PATH_MAX+1];
// };

int im_server_main(void);
int im_server_init(void);
int im_rcvmsg_deal(struct per_session_data__minimal *pss, char* pmsg,
	int msg_len,char* retmsg,int* retmsg_len,int* ret_flag,int* plws_index);
int lws_send_onemsg(int id,struct lws *wsi,int* break_flag);
int imuser_friendstatus_push(int index,int online_status);
int im_nodelist_addfriend(int index,char* from_user,char* to_user,char* nickname,char* userkey);
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
int post_newmsg_notice(char* rid,char* targetid,char* msgpay,int server_flag,int msgid);
int im_debug_setfunc_deal(char* pcmd);
int pnr_relogin_push(int index,int curtox_flag,int cur_fnum,struct per_session_data__minimal *cur_pss);
int pnr_encrypt_show(char* msg,int flag);
int pnr_check_update_devinfo_bytoxid(int index,char* ftox_id,char* dev_id,char* dev_name);
int im_simulation_setfunc_deal(char* pcmd);
int im_group_fileinfo_analyze(char* fileinfo,struct group_fileinfo_struct* pfinfo);
int post_devinfo_upload_once(void* param);
void* post_devinfo_upload_task(void *para);
void* post_newmsgs_loop_task(void *para);
int pnr_post_attach_touser(char* uid);
int pnr_router_node_friend_init(void);
int get_rnodefidbytoxid(char* p_toxid);
int pnr_relogin_pushbylws(int index,int type);
int pnr_relogin_pushbytox(int index,int type);
void *pnr_dev_register_task(void *para);
int pnr_rnode_debugmsg_send(char* pcmd);
void *self_monitor_thread(void *para);
int im_debug_pushnewnotice_deal(char* pbuf);
int pnr_sysoperation_done(int type);
int pnr_config_user_capacity(int index,unsigned int capacity);
int pnr_get_user_capacity(int index,unsigned int* capacity);
int get_user_volume(int uindex,unsigned int* volume);
int pnr_cmdbylws_handle(struct per_session_data__minimal *pss,char* pmsg,
	int msg_len,char* retmsg,int* retmsg_len,int* ret_flag,int* plws_index);
#endif
