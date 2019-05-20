#ifndef COMMON_LIB_H
#define COMMON_LIB_H

#include <stdio.h>

#ifndef OK
#define OK 0
#endif

#ifndef ERROR
#define ERROR 1
#endif

#ifndef TRUE
#define TRUE 1
#endif

#ifndef FALSE
#define FALSE 0
#endif

typedef  unsigned char uint8;
typedef  unsigned short uint16;
typedef  unsigned int uint32;
typedef  char int8;
typedef  short int16;
typedef  int int32;
typedef  unsigned long long uint64;
typedef  long long int64;

#define RETRY_SEND_MAXTIME 5
#define MAC_LEN 6
#define IPSTR_MAX_LEN 64
#define MACSTR_MAX_LEN 18
#define VERSION_MAXLEN   32
#define URL_MAX_LEN 1024
#define BUF_LINE_MAX_LEN 2048
#define ENCODEBUF_LINE_MAX_LEN 4096
#define POST_RET_MAX_LEN 40960
#define TIMESTAMP_STRING_MAXLEN  128
#define MANU_NAME_MAXLEN 256
#define MANU_CODE_MAXLEN 256
#define ENCRYPTION_TYPE_MAXLEN 64
#define ENCRYPTION_KEY_MAXLEN 256
#define IM_MSG_MAXLEN    2048
#define IM_MSG_PAYLOAD_MAXLEN    1024
#define IM_JSON_MAXLEN    65535
#define ID_TYPE_STRING_MAXLEN 4
#define ID_CODE_STRING_MAXLEN 128
#define DEFAULT_DES_KEYLEN   8
#define PNR_FILENAME_MAXLEN 160
#define PNR_FILEINFO_MAXLEN 94
#define PNR_FILEPATH_MAXLEN 320
#define PNR_USERNAME_MAXLEN 128
#define LOGINTIME_PAYLOAD "XXXXXXXXXXXXXXXXXXX" //yyyy-MM-dd HH:mm:ss
#define LOGINTIME_PAYLOAD_LEN 19 //yyyy-MM-dd HH:mm:ss
#define LOGINTIME_PAYLOAD2 "XXXXXXXXXXXXXX" //yyyyMMddHHmmss
#define LOGINTIME_PAYLOAD2_LEN 14 //yyyyMMddHHmmss
#define DATAFILE_BUFF_MAXLEN    8*1024
#define DATAFILE_BASE64_ENCODE_MAXLEN    12*1024//base64编码之后最多为原长度/3*4
#define LOGINTIME_PAYLOAD2_OFFSET (LOGINTIME_PAYLOAD_LEN+1)
#define DEAMON_PIDFILE  "/tmp/pnrouter_pid"
#define CMD_MAXLEN 1024
#define TOX_ID_STR_LEN   76
#define DAEMON_FIFONAME  "/tmp/pnrouter_msg.fifo"
#define DAEMON_OPEN_FIFONAME_CMD  "cat /tmp/pnrouter_msg.fifo"
#define LOG_PATH "/tmp/logdisk/pnrouter_debug.log"
#define PNR_USER_PUBKEY_MAXLEN      512//这里是256字节然后再base64转码之后的长度
#define PNR_FRIEND_MSG_MAXLEN      512
#define PNR_DEBUG_FILENAME  "/tmp/pnr_debug.info"
#define PNR_STATUS_FILENAME  "/tmp/pnr_status.info"
#define PNR_ADMINUSER_SN  "AdminUserQrcode"
#define PNR_ADMINUSER_MNEMONIC     "QURNSU4gVVNFUg==" //admin user base64code
#define PNR_NORMALUSER_MNEMONIC     "Tk9STUFMIFVTRVI=" //normal user base64code
#define PNR_TEMPUSER_MNEMONIC     "VEVNUCBVU0VS" //temp user base64code
#define PNR_CUR_NORMALUSER_NUM "NormalUserNum"
#define PNR_CUR_TEMPUSER_NUM "TempUserNum"
#define PNR_TOTAL_STORAGE_SPACE  "TotalStroageSpace"
#define PNR_FREE_STORAGE_SPACE  "FreeStroageSpace"
#define PNR_RSA_KEY_MAXLEN 255
#define DEV_ETH0_KEYNAME  "eth0"
#define DEV_ETH1_KEYNAME  "eth1"
#define PNR_USN_KEY_VERSION  0x010001
#define PNR_USN_KEY_VERSION_STR  "010001"
#define PNR_USN_KEYVER_LEN   6
#define PNR_USN_KEY_V101_WORD   "welcometoqlc0101"
#define PNR_USN_KEY_V101_WORDLEN   16
#define PNR_USN_IVKEY_V101_WORD  "AABBCCDDEEFFGGHH"
#define PNR_AES_CBC_KEYSIZE 128
#define PNR_USN_MAXLEN  32
#define PNR_MD5_VALUE_MAXLEN 32
#define PNR_IDCODE_MAXLEN  8
#define PNR_LOGINKEY_MAXLEN  64
#define PNR_QRCODE_SRCLEN    (PNR_USN_KEYVER_LEN+TOX_ID_STR_LEN+PNR_USN_MAXLEN)
#define PNR_QRCODE_MAXLEN 255
#define PNR_USER_HASHID_MAXLEN 16
#define PNR_DISK_MAXNUM 2

#define PNR_FRPC_CONFIG_FILE "/etc/frpc.ini"
#define PNR_FRPC_CONFIG_TMPFILE "/tmp/frpc.ini"
#define PNR_REPEAT_TIME_15SEC    15// 15second
#define PNR_REPEAT_TIME_30SEC    30// 30second
#define PNR_REPEAT_TIME_1MIN    60// 1min
#define PNR_REPEAT_TIME_15MIN   900//15min
#define PNR_FRPC_CONNSTATUS_OKKEY "proxy success"

//用户类型
enum PNR_USER_TYPE_ENUM
{
    PNR_USER_TYPE_ADMIN = 0x01,
    PNR_USER_TYPE_NORMAL,
    PNR_USER_TYPE_TEMP,
    PNR_USER_TYPE_BUTT
};
enum PNR_DEV_TYPE_ENUM
{
    PNR_DEV_TYPE_X86SERVER = 1,
    PNR_DEV_TYPE_ONESPACE = 2,
    PNR_DEV_TYPE_RASIPI3 = 3,
    PNR_DEV_TYPE_EXPRESSOBIN = 4,
};
#define PNR_QRCODE_HEADOFFSET  7
enum PNR_QRCODE_TYPE_ENUM
{
    PNR_QRCODE_TYPE_USERINFO = 0,
    PNR_QRCODE_TYPE_ACCOUNTINFO = 1,
    PNR_QRCODE_TYPE_DEVINFO = 2,
    PNR_QRCODE_TYPE_APPKEY = 3,
    PNR_QRCODE_TYPE_BUTT
};

enum {
	PNR_BUF_LEN_128		= 128,
	PNR_BUF_LEN_256		= 256,
	PNR_BUF_LEN_512		= 512,
	PNR_BUF_LEN_1024	= 1024,
};

#define PNR_TOXINSTANCE_CREATETIME   10
#define PNR_DATAFILE_DEFNAME     "data.ini"
#ifdef OPENWRT_ARCH 
#define PNR_IMUSER_MAXNUM 100
#define PNR_GROUP_MAXNUM 30
#define PNR_GROUP_USER_MAXNUM 50
#elif DEV_ONESPACE
#define PNR_IMUSER_MAXNUM 100
#define PNR_GROUP_MAXNUM 30
#define PNR_GROUP_USER_MAXNUM 50
#else
#define PNR_IMUSER_MAXNUM 300
#define PNR_GROUP_MAXNUM 50
#define PNR_GROUP_USER_MAXNUM 100
#endif
#define PNR_IMUSER_FRIENDS_MAXNUM 200//单个用户最大200个好友
#define PNR_INDEX_HASHSTR_LEN 3
#define PNR_BKDR_HASHSTR_LEN 8
#define PNR_HASHID_MAXNUM   (PNR_IMUSER_FRIENDS_MAXNUM*PNR_IMUSER_MAXNUM)
#define PNR_DEFAULT_DAEMON_USERINDEX    0//主通信tox用户
#define PNR_DEFAULT_DATAVERSION  1
#define PNR_ADMINUSER_PSN_INDEX    1 //默认给客户的admin账号只有一个
#define PNR_ADMINUSER_DEFAULT_IDCODE    "QLCADMIN"
#define PNR_TEMPUSER_PSN_INDEX    0xF00001
#define PNR_USN_USERTYPE_LEN   2
#define PNR_USN_USERSEQ_LEN   6
#define USERDEBUG
enum DEBUG_LEVEL
{
    DEBUG_LEVEL_INFO         = 1,
    DEBUG_LEVEL_NORMAL,
    DEBUG_LEVEL_ERROR,
};
#define SYSINFO_CHECK_CYCLE      600  //10* 60
#define HEARTBEAT_CYCLE      60  //60sec
#define IMUSER_HEARTBEAT_CYCLE 30//30sec
#define PNR_SELF_MONITOR_CYCLE   60 // 1min
#ifdef USERDEBUG
#define DEBUG_INIT(file) log_init(file)
#define DEBUG_LEVEL(level) log_level(level)
#define DEBUG_PRINT(level,format...)\
    log_print_to_file(level, __FILE__, __LINE__,__func__,format)
#else
#define DEBUG_PRINT(level,format...) //do{printf(format);printf("\n");}while(0)
#endif

typedef struct curl_buf
{
	char * pos;
	char * buf;
	unsigned int len;
}tCurlBuf;
struct arg_opts_struct {
    char version_flag;
    char help_flag;
    char qrcode_showmode;
};
#define CJSON_GET_VARSTR_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                if(tmp_json_buff[0] == '\"')\
                {\
                    if(tmp_json_buff[strlen(tmp_json_buff)-1] == '\"')\
                    {\
                        tmp_json_buff[strlen(tmp_json_buff)-1] = 0;\
                    }\
                    strncpy(var,tmp_json_buff+1,len);\
                }\
                else\
                {\
                    strncpy(var,tmp_json_buff,len);\
                }\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            memset(var,0,len);\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }
#define CJSON_GET_VARFLOAT_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                if(tmp_json_buff[0] == '\"')\
                {\
                    var=(int)(atof(tmp_json_buff+1) * 100);\
                }\
                else\
                {\
                    var=(int)(atof(tmp_json_buff) * 100);\
                }\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            var = 0;\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }
#define CJSON_GET_VARINT_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                if(tmp_json_buff[0] == '\"')\
                {\
                    var = atoi(tmp_json_buff+1);\
                }\
                else\
                {\
                    var = atoi(tmp_json_buff);\
                }\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            var = 0;\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }
#define CJSON_GET_VARLONG_BYKEYWORD(item,tmpItem,tmp_json_buff,key,var,len) \
    {\
        tmpItem=cJSON_GetObjectItem(item,key);\
        if(tmpItem != NULL)\
        {\
            tmp_json_buff = cJSON_PrintUnformatted(tmpItem);\
            if(tmp_json_buff != NULL)\
            {\
                if(tmp_json_buff[0] == '\"')\
                {\
                    var = atol(tmp_json_buff+1);\
                }\
                else\
                {\
                    var = atol(tmp_json_buff);\
                }\
                free(tmp_json_buff);\
            }\
        }\
        else\
        {\
            var = 0;\
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get key(%s) failed",key);\
        }\
    }

//list 
struct list_head {
    struct list_head *next;
    struct list_head *prev;
};
 
#define LIST_HEAD_INIT(name) { &(name), &(name) }
 
#define LIST_HEAD(name) \
    struct list_head name = LIST_HEAD_INIT(name)
 
 
static inline void INIT_LIST_HEAD(struct list_head *list)
{
    list->next = list;
    list->prev = list;
}
 
static inline void __list_add(struct list_head *item,
                 struct list_head *prev,
                 struct list_head *next)
{
    prev->next = item;
    item->prev = prev;
    next->prev = item;
    item->next = next;
}
 
static inline void list_add_tail(struct list_head *item,
                    struct list_head *head)
{
    __list_add(item, head->prev, head);
}
 
static inline void list_add_head(struct list_head *item,
                    struct list_head *head)
{
    __list_add(item, head, head->next);
}
 
static inline void list_add(struct list_head *item,
                    struct list_head *head)
{
    __list_add(item, head, head->next);
}
 
static inline void list_add_prev(struct list_head *item,
                    struct list_head *head)
{
    __list_add(item, head->prev, head);
}

static inline void list_add_before(struct list_head *item,
                    struct list_head *next)
{
	item->next = next;
	item->prev = next->prev;
	next->prev->next = item;
	next->prev = item;
}

static inline void list_del(struct list_head *item)
{
    item->next->prev = item->prev;
    item->prev->next = item->next;
    item->next = NULL;
    item->prev = NULL;
}
 
static inline int list_empty(struct list_head *list)
{
    return list->next == list;
}
 
static inline unsigned int list_length(struct list_head *list)
{
    struct list_head *item;
    int count = 0;
    for (item = list->next; item != list; item = item->next)
        count++;
    return count;
}

#ifndef offsetof
#define offsetof(type, member) ((long) &((type *) 0)->member)
#endif
 
#ifndef container_of
#define container_of(ptr, type, member) \
    ((type *) ((char *) ptr - offsetof(type, member)))
#endif
 
#define list_entry container_of
 
#define list_first_entry(list, type, member) \
    (list_empty((list)) ? NULL : \
     list_entry((list)->next, type, member))
 
#define list_last_entry(list, type, member) \
    (list_empty((list)) ? NULL : \
     list_entry((list)->prev, type, member))
 
#define list_entry_prev list_last_entry
 
#define list_entry_next list_first_entry
 
#define list_for_each(item, list, type, member) \
    for (item = list_entry((list)->next, type, member); \
         &item->member != (list); \
         item = list_entry(item->member.next, type, member))
 
#define list_for_each_safe(item, n, list, type, member) \
    for (item = list_entry((list)->next,type, member), \
             n = list_entry(item->member.next, type, member); \
         &item->member != (list); \
         item = n, n = list_entry(n->member.next, type, member))
 
#define llist_for_each_reverse(item, list, type, member) \
    for (item = list_entry((list)->prev, type, member); \
         &item->member != (list); \
         item = list_entry(item->member.prev, type, member))

#define STROAGE_BUFFER_STRINGLEN   32
enum STROAGE_BYTETYPE_ENUM
{
    STROAGE_BYTETYPE_KB = 1,
    STROAGE_BYTETYPE_MB,
    STROAGE_BYTETYPE_GB,
    STROAGE_BYTETYPE_BUTT,
};
#define STROAGE_INFO_PARAMS(str,num,type)\
    {\
        num = atoi(str);\
        if(strchr(str,'G') != NULL){\
            type = STROAGE_BYTETYPE_GB;\
        }else if(strchr(str,'M') != NULL){\
            type = STROAGE_BYTETYPE_MB;\
        }else{\
            type = STROAGE_BYTETYPE_KB;\
        }\
    }
struct stroage_info_struct
{
    int total_num;
    int total_bytetype;
    int used_num;
    int used_bytetype;
    int free_num;
    int free_bytetype;
    int percent;
    char total_info_string[STROAGE_BUFFER_STRINGLEN];
    char used_info_string[STROAGE_BUFFER_STRINGLEN];
    char free_info_string[STROAGE_BUFFER_STRINGLEN];
    char used_percent[STROAGE_BUFFER_STRINGLEN];
};

enum PNRDEV_NETCONN_TYPE
{
    PNRDEV_NETCONN_UNKNOWN = 0,
    PNRDEV_NETCONN_PUBDIRECT = 1,
    PNRDEV_NETCONN_FRPPROXY = 2,
};
enum PNRDEV_FRPCONNCT_TYPE
{
    PNRDEV_FRPCONNCT_OFF = 0,
    PNRDEV_FRPCONNCT_SSHSEVER = 1,
    PNRDEV_FRPCONNCT_PNRSEVER = 2,
};
#define PNR_ATTACH_INFO_MAXLEN 512
struct pnrdev_netconn_info
{
    int pubnet_mode;
    int frp_mode;
    int conn_status;
    int pnr_port;
    int ssh_port;
    int frp_port;
    char pub_ipstr[IPSTR_MAX_LEN+1];
    char attach[PNR_ATTACH_INFO_MAXLEN+1];
};
struct pnrdev_register_info
{
    int dev_type;
    char rid[TOX_ID_STR_LEN+1];
    char eth0_mac[MACSTR_MAX_LEN+1];
    char eth1_mac[MACSTR_MAX_LEN+1];
    char eth0_localip[IPSTR_MAX_LEN+1];
    char eth1_localip[IPSTR_MAX_LEN+1];
    char version[PNR_QRCODE_MAXLEN+1];
};
struct pnrdev_register_resp
{
    int ret;
    int index;
    int pubnet_mode;
    int frp_mode;
    int renew_flag;
    int pnr_port;
    int ssh_port;
    int frp_port;
    char pub_ipstr[IPSTR_MAX_LEN+1];
    char rid[TOX_ID_STR_LEN+1];
    char eth0_mac[MACSTR_MAX_LEN+1];
};
//function declaration
int get_cmd_ret(char* pcmd);
//unsigned int ip_aton(const char* ip);
//char* ip_ntoa(unsigned int ip);
char *mac_to_str(unsigned char *mac);
void log_init(char *file);
void log_level(int level);
int log_print_to_file(int level, char* file,int line,const char *func,char *fmt,...);
int check_ip_string(const char *ip);
unsigned int convert_str2ip(const char *ipaddr);
int post_info_to_idc(char *host, char *url, char *post_fields, char *ret_buf);
int urlencode(char* str,int strSize, char* result, const int resultSize);
unsigned char* urldecode(unsigned char* encd,unsigned char* decd);
int cjson_get_keyword_string(char* pbuf,char* pkey,char* pret);
int cjson_ret_stauts_check(char * pbuf);
int strtotime(char* datetime);
int get_meminfo(void);
int get_storageinfo(struct stroage_info_struct* psinfo);
int pnr_base64_encode(const char *indata, int inlen, char *outdata, int *outlen);
int pnr_base64_decode(const char *indata, int inlen, char *outdata, int *outlen);
int get_hwaddr_byname(char* devname,char* hwaddr_full,char* hwaddr);
int pnr_create_usersn(int user_type,int user_index,char* p_usn);
int pnr_qrcode_create_png(char* src_string,char* dst_filename);
int pnr_qrcode_create_utf8(char* src_string,char* dst_filename);
int pnr_qrcode_create_png_bycmd(char* src_string,char* dst_filename);
int get_file_name(FILE *pf, char *path, int len);
int get_file_size(char* filename);
void pnr_itoa (int n,char* pstr);
int get_file_content(char *path, char *buf, int len);
int get_popen_content(char *cmd, char *buf, int len);

#ifdef OPENWRT_ARCH
char* uci_get_config_value(const char* package,
    const char* type, char *name, const char* option, char* val, unsigned int 
len,char *path);
int uci_get_config_value_int(const char* package,
    const char* type, char *name, const char* option, int* value,char* dir);
#endif
int https_post(char *host, int port, char *url, const char *data, int dsize, char *buff, int bsize);
int dev_hwaddr_init(void);
unsigned int pnr_BKDRHash(char *str);
int pnr_uidhash_get(int u_index,int f_num,char* tox_id,unsigned int* hashnum,char* p_ret_hashstr);
int pnr_htoi(char* s);
int get_disk_capacity(int disk_count,char* used_capacity,char* total_capacity,int* percent);
int pnr_sign_check(char* sign,int sign_len,char* pubkey,int base64encode_flag);
int pnr_devinfo_get(struct pnrdev_register_info* pinfo);
int pnr_check_process_byname(char* pname,int* pid);
int get_localip_byname(char* devname,char* local_ip);
int pnr_check_frp_connstatus(void);
char* pnr_stristr (const char * str1,const char * str2);
#endif

