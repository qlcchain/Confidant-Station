#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <ctype.h>
#include <time.h>
#include <arpa/inet.h>
#include <common_lib.h>
#include <curl/curl.h>
#include <sys/file.h>
#include <sys/stat.h> 
#include "sodium.h"
#ifdef OPENWRT_ARCH
#include <uci.h>
#endif
#include "md5.h"
#include "aes.h"

char log_path[64];
int g_debug_level = DEBUG_LEVEL_NORMAL;
int g_mem_total = 0;
int g_mem_free = 0;

#define AUTHUSERCMDPARSELINE(buff,phead,ptail,line,fp)\
{\
    phead =strchr(buff,':');\
    if(phead == NULL)\
    {\
        pclose(fp);\
        return ERROR;\
    }\
    phead ++;\
    ptail = strchr(phead,';');\
    if(ptail == NULL)\
    {\
        pclose(fp);\
        return ERROR;\
    }\
    ptail[0] = '\0';\
}
int get_cmd_ret(char* pcmd)
{
    int line = 0;
    long int ret = 0;
    FILE *fp = NULL;
    char *p_head = NULL;
    char * p_tail = NULL;
    char buff[BUF_LINE_MAX_LEN];

    memset(buff, 0, sizeof(buff));
    
    if(pcmd == NULL)
    {
        return ERROR;
    }

    if (!(fp = popen(pcmd, "r"))) 
    {
        return ERROR;
    }

    while(NULL != fgets(buff, BUF_LINE_MAX_LEN, fp)) 
    {
        if(line == 0)
        {
            AUTHUSERCMDPARSELINE(buff,p_head,p_tail,line,fp);
            ret = strtol(p_head, (char **) NULL, 16);
            if(ret != OK)
            {
                pclose(fp);
                return ERROR;
            }
            break;
        }
    }

    pclose(fp);
    return OK;
}

#if 0
unsigned int ip_aton(const char* ip)
{
	struct in_addr ip_addr;
	if( inet_aton(ip, &ip_addr) )
    {   
		return ip_addr.s_addr;
    }   
	return OK;
}

char* ip_ntoa(unsigned int ip)
{
	struct in_addr ip_addr;

    ip_addr.s_addr = htonl(ip);  
	return inet_ntoa(ip_addr);
}
#endif
char *mac_to_str(unsigned char *mac)
{
	static char str[32];

	memset(str, 0x00, sizeof(str));
	sprintf(str, "%02X:%02X:%02X:%02X:%02X:%02X", 
        (unsigned int)mac[0], 
        (unsigned int)mac[1], 
        (unsigned int)mac[2], 
        (unsigned int)mac[3], 
        (unsigned int)mac[4], 
        (unsigned int)mac[5]);
	return str;
}

void log_init(char *file)
{
    memset(log_path, 0, sizeof(log_path));
    strcpy(log_path, file);
}

void log_level(int level)
{
    g_debug_level = level;
}

int log_print_to_file(int level, char* file,int line,const char *func,char *fmt,...)
{
    va_list args;
    //time_t t = time(NULL);
    char time_str[TIMESTAMP_STRING_MAXLEN] = {0};
    //struct tm date;
    //struct tm* tp;
    FILE *log_fp = NULL;
    int fd_no = 0;
    //memset(time_str, 0, TIMESTAMP_STRING_MAXLEN);

    if(g_debug_level > level)
    {
        return ERROR;
    }
    	
    //tp= localtime_r(&t,&date);
    if((log_fp = fopen(log_path, "a")) == NULL)
    {
        return ERROR;
    }
    fd_no = fileno(log_fp);
    flock(fd_no,LOCK_EX);
	//strftime(time_str,100,"[%Y-%m-%d-%H:%M:%S] ",tp);
	snprintf(time_str,TIMESTAMP_STRING_MAXLEN,"[%s:%d:%s %d]",file,line,func,(int)time(NULL));
	//snprintf(time_str,TIMESTAMP_STRING_MAXLEN,"[  ]");
    fprintf(log_fp,"%s",time_str);
    va_start(args,fmt);
    vfprintf(log_fp,fmt,args);
    va_end(args);
    fprintf(log_fp,"\n");
    fclose(log_fp);
    flock(fd_no, LOCK_UN);
    return OK;
}


int check_ip_string(const char *ip)
{
    int  i = 0,  len = strlen(ip);

    for(; i < len; ++i)
    {
        if(! ((ip[i] <= '9' && ip[i] >= '0') ||(ip[i] == '.')))
        {
             return  -1;
        }
    }
    return OK;
}

unsigned int convert_str2ip(const char *ipaddr)
{
	unsigned int b[4]= {0,0,0,0};

	sscanf(ipaddr, "%u.%u.%u.%u", &b[0], &b[1], &b[2], &b[3]);
	return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3];
}
#ifdef OPENWRT_ARCH
char* uci_get_config_value(const char* package,
    const char* type, char *name, const char* option, char* val, unsigned int 
len,char *path)
{
    unsigned int vallen;
	struct uci_context *uci = NULL;
	struct uci_package *p = NULL;
	struct uci_section *s;
	struct uci_element *e;
	struct uci_ptr* ptr;
	struct uci_ptr pptr = { .package = package };

    if (!package || !type || !option || !val)
		goto out;
    memset(val, 0, len);

    ptr = &pptr;
    ptr->package = package;

    uci = uci_alloc_context();
    if (!uci) {
		goto out;
    }
    uci_set_confdir(uci,path);
	uci_load(uci, ptr->package, &p);
	if (!p)
		goto out;

	uci_foreach_element(&p->sections, e) {
		s = uci_to_section(e);

		if (strcmp(s->type, type))
		{
			continue;
		}

		ptr->section = s->e.name;
		ptr->s = NULL;

		ptr->option = option;
        ptr->o = NULL;

        if (name && ptr->section && strcmp(ptr->section, name))
            continue;

		if (uci_lookup_ptr(uci, ptr, NULL, true))
			continue;

        if (!(ptr->flags & UCI_LOOKUP_COMPLETE))
			continue;

        if (ptr->o->type != UCI_TYPE_STRING)
			continue;

        vallen = strlen(ptr->o->v.string);
        len = vallen > len ? len : vallen;
        memcpy(val, ptr->o->v.string, len);
        break;
	}

	if (uci)
		uci_free_context(uci);
    return val;
out:
    if (uci)
		uci_free_context(uci);
    return NULL;
}

int uci_get_config_value_int(const char* package,
    const char* type, char *name, const char* option, int* value,char* dir)
{
    char buf[16] = {0};
	
    if (uci_get_config_value(package,type,name,option,buf,16,dir) == NULL)
    {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"uci_get_config_value error");
		return -1;
	}
    *value = atoi(buf);
    return *value;
}
#endif
static size_t post_idc_func( void *ptr, size_t size, size_t nmemb, void *stream)
{
	tCurlBuf * buf;
	int tmp_len = 0;
	buf = (tCurlBuf *)stream;

	if(buf->len + nmemb >= POST_RET_MAX_LEN)
	{
		tmp_len = POST_RET_MAX_LEN - 1 - buf->len;
		if(tmp_len <= 0)
		{
			return 0;
		}
	}
	else
	{
		tmp_len = nmemb;
	}

	memcpy(buf->pos,ptr,tmp_len);
	buf->pos[tmp_len] = 0;
	buf->pos += tmp_len;
	buf->len += tmp_len;

	return tmp_len;
}
int post_info_to_idc(char *host, char *url, char *post_fields, char *ret_buf)
{
	CURLcode return_code;
	CURL *easy_handle;
	char t_url[1024] = {0};
	tCurlBuf buf;
	int ret_len = -1;
	struct curl_slist* headers = NULL;
	
	easy_handle = curl_easy_init();
	snprintf(t_url,1024,"http://%s%s",host,url);
	curl_easy_setopt(easy_handle, CURLOPT_URL,t_url);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:post t_url(%s)",t_url);

	buf.buf = ret_buf;
	buf.pos = ret_buf;
	buf.len = 0;
	curl_easy_setopt(easy_handle,CURLOPT_WRITEFUNCTION,post_idc_func);

	//设置http发送的内容类型为JSON
    //构建HTTP报文头  
	//增加HTTP header
	headers = curl_slist_append(headers, "Accept:application/json");
	headers = curl_slist_append(headers, "Content-Type:application/json");
	headers = curl_slist_append(headers, "charset:utf-8");
	curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, headers);
	//curl_easy_setopt(easy_handle,CURLOPT_HEADER,0);

	curl_easy_setopt(easy_handle,CURLOPT_WRITEDATA,&buf);
	curl_easy_setopt(easy_handle,CURLOPT_POST, 1);
	curl_easy_setopt(easy_handle,CURLOPT_POSTFIELDS, post_fields);
	curl_easy_setopt(easy_handle,CURLOPT_NOSIGNAL, 1);
	curl_easy_setopt(easy_handle,CURLOPT_CONNECTTIMEOUT, 10);
	curl_easy_setopt(easy_handle,CURLOPT_TIMEOUT, 5);
    curl_easy_setopt(easy_handle, CURLOPT_IPRESOLVE, CURL_IPRESOLVE_V4);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:set post_fields(%s)",post_fields);
	return_code = curl_easy_perform(easy_handle);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"post_info_to_idc:return_code(%d)",return_code);
	if (CURLE_OK != return_code)
	{
		ret_len = 0;
		goto exit;
	}
	ret_len = buf.pos - buf.buf;

exit:
	curl_slist_free_all(headers); /* free the list again */
	curl_easy_cleanup(easy_handle);	
	return ret_len;
}

/**********************************************************************************
  Function:      urlencode
  Description:  字符串的url编码
  Calls:
  Called By:
  Input:         char* str
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int urlencode(char* str,int strSize, char* result, const int resultSize)
{
    int i;
    int j = 0;
    char ch;
 
    if ((str==NULL) || (result==NULL) || (strSize<=0) || (resultSize<=0)) 
    {
        return -1;
    }
 
    for ( i=0; (i<strSize)&&(j<resultSize); ++i) 
	{
        ch = str[i];
        if (((ch>='A') && (ch<'Z')) ||
            ((ch>='a') && (ch<'z')) ||
            ((ch>='0') && (ch<'9'))) 
	    {
            result[j++] = ch;
        } 
		else if (ch == ' ') 
		{
            result[j++] = '+';
        } 
		else if (ch == '.' || ch == '-' || ch == '_' || ch == '*')
		{
            result[j++] = ch;
        } 
		else 
		{
            if (j+3 < resultSize) 
            {
                sprintf(result+j, "%%%02X", (unsigned char)ch);
                j += 3;
            } 
            else 
            {
                return -1;
            }
        }
    }
 
    result[j] = '\0';
    return j;
}

//解url编码实现 
unsigned char* urldecode(unsigned char* encd,unsigned char* decd) 
{ 
    int j,i; 
    char *cd = (char*)encd; 
    char p[2]; 
    //unsigned int num; 
	j=0; 

    for( i = 0; i < strlen(cd); i++ ) 
    { 
        if( cd[i] != '%' ) 
        { 
            decd[j++] = cd[i]; 
            continue; 
        } 
        memset( p, 0, 2);   
  		p[0] = cd[++i]; 
        p[1] = cd[++i]; 

        p[0] = p[0] - 48 - ((p[0] >= 'A') ? 7 : 0) - ((p[0] >= 'a') ? 32 : 0); 
        p[1] = p[1] - 48 - ((p[1] >= 'A') ? 7 : 0) - ((p[1] >= 'a') ? 32 : 0); 
        decd[j++] = (unsigned char)(p[0] * 16 + p[1]); 
    }  
    return decd; 
}

int cjson_get_keyword_string(char* pbuf,char* pkey,char* pret)
{
	char ptmp_buff[BUF_LINE_MAX_LEN] = {0};
	char* ptmp = NULL;
	char* pend = NULL;
	if(pbuf == NULL || pkey == NULL)
	{
		return ERROR;
	}
	memset(pret,0,BUF_LINE_MAX_LEN);
	snprintf(ptmp_buff,BUF_LINE_MAX_LEN,"\"%s\":",pkey);
	ptmp = strstr(pbuf,ptmp_buff);
	if(ptmp == NULL)
	{
		return ERROR;
	}
	ptmp += strlen(ptmp_buff);
	if(ptmp[0] == '\"')
	{
		ptmp++;
		pend = strchr(ptmp,'\"');
		if(pend == NULL)
		{
			return ERROR;
		}
		if(pend == ptmp)
		{
			strcpy(pret,"NULL");
		}
		else
		{
			strncpy(pret,ptmp,pend-ptmp);
		}
	}
	else
	{
		pend = strchr(ptmp,',');
		if(pend == NULL)
		{
			return ERROR;
		}
		if(pend == ptmp)
		{
			strcpy(pret,"NULL");
		}
		else
		{
			strncpy(pret,ptmp,pend-ptmp);
		}
	}
	return OK;
}
int strtotime(char* datetime)
{  
	struct tm tm_time;  
	int unixtime;  
	strptime(datetime,"%Y-%m-%d %H:%M:%S",&tm_time);  
	  
	unixtime = mktime(&tm_time);  
	return unixtime;  
}
#if 0
/**********************************************************************************
  Function:      qlv_put_params_string
  Description:  字符串的url编码
  Calls:
  Called By:
  Input:         char* str
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int qlv_put_params_string(char* string,char* key,char* value,int appendflag)
{
    if(appendflag == TRUE)
    {
        strcat(string,"&");
    }
    strcat(string,key);
    strcat(string,"=");
    if(value != NULL)
    {
        strcat(string,value);
    }
    return OK;
}
/**********************************************************************************
  Function:      qlv_get_md5sign
  Description:  字符串的url编码
  Calls:
  Called By:
  Input:         char* str
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int qlv_get_md5sign(char* src_string,char* out_sign)
{
    char tmp_string[ENCODEBUF_LINE_MAX_LEN] = {0};
    strcpy(tmp_string,src_string);
    strcat(tmp_string,QLV_MD5_KEYWORD);
	strcpy(out_sign,md5_hash((unsigned char *)tmp_string, strlen((const char *)tmp_string)));
    return OK;
}
#endif

/**********************************************************************************
  Function:      get_meminfo
  Description:  获取内存使用情况
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_meminfo(void)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    FILE *fp = NULL;

    if(g_mem_total == 0)
    {
#ifdef OPENWRT_ARCH
        snprintf(cmd,CMD_MAXLEN,"cat /proc/meminfo |grep MemTotal");
#else
        snprintf(cmd,CMD_MAXLEN,"cat /proc/meminfo |grep MemTotal");
#endif
        if (!(fp = popen(cmd, "r"))) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
            return ERROR;
        }
        if (fgets(recv,CMD_MAXLEN,fp) <= 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
            pclose(fp);
            return ERROR;
        }  
        pclose(fp);
        g_mem_total = atoi(&recv[10]);
    }

#ifdef OPENWRT_ARCH
    snprintf(cmd,CMD_MAXLEN,"cat /proc/meminfo |grep MemFree");
#else
    snprintf(cmd,CMD_MAXLEN,"cat /proc/meminfo |grep MemFree");
#endif
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp);
    g_mem_free = atoi(&recv[10]);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"MemTotal(%d) MemFree(%d)",g_mem_total,g_mem_free);
    return OK;
}
extern int g_pnrdevtype;
/**********************************************************************************
  Function:      get_disk_capacity
  Description:  获取磁盘容量
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_disk_capacity(int disk_count,char* used_capacity,char* total_capacity,int* percent)
{
    if(used_capacity == NULL || total_capacity == NULL)
    {
        return ERROR;
    }
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    FILE *fp = NULL;
    char* pbuf = NULL;
    int stok_flag = 0;

    if(disk_count <0 || disk_count > PNR_DISK_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"input bad disk_count(%d)",disk_count);
        return ERROR;
    }
    
    switch(g_pnrdevtype)
    {
        case PNR_DEV_TYPE_X86SERVER:
            snprintf(cmd,CMD_MAXLEN,"df -h |grep /dev/?da");
            break;
        case PNR_DEV_TYPE_ONESPACE:
            if(disk_count == 0)
            {   
                snprintf(cmd,CMD_MAXLEN,"df -h |grep /dev/root");
            }
            else
            {
                snprintf(cmd,CMD_MAXLEN,"df -h |grep sata");
            }
            break;
        case PNR_DEV_TYPE_RASIPI3:
        case PNR_DEV_TYPE_EXPRESSOBIN:
            snprintf(cmd,CMD_MAXLEN,"df -h |grep /usr");
            break;
    }
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_disk_capacity cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_disk_capacity cmd =%s ret failed",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp); 
    pbuf = strtok(recv," ");
    while(pbuf != NULL)
    {
        stok_flag++;
        if(stok_flag == 2)
        {
            strcpy(total_capacity,pbuf);
        }
        if(stok_flag == 3)
        {
            strcpy(used_capacity,pbuf);
        }
        if(stok_flag == 5)
        {
            *percent = atoi(pbuf);
            break;
        }
        pbuf = strtok(NULL," ");
    }
    if(stok_flag != 5)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_disk_capacity:recv(%s)",recv);
        return ERROR;
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get_disk_capacity:get disk(%s %s %d)",used_capacity,total_capacity,*percent);
    return OK;
}

/**********************************************************************************
  Function:      get_file_md5value
  Description:  获取文件MD5值
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_file_md5value(char* filename,char* md5_value)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    FILE *fp = NULL;

    if(filename == NULL)
    {
        return ERROR;
    }
    if(access(filename,F_OK) != OK)
    {
        return ERROR;
    }
#ifdef OPENWRT_ARCH
    snprintf(cmd,CMD_MAXLEN,"md5sum %s",filename);
#else
    snprintf(cmd,CMD_MAXLEN,"md5sum %s",filename);
#endif
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp);
    strncpy(md5_value,recv,PNR_MD5_VALUE_MAXLEN);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get file(%s) md5_value(%s)",filename,md5_value);
    return OK;
}

/**********************************************************************************
  Function:      get_storageinfo
  Description:  获取存储使用情况
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_storageinfo(struct stroage_info_struct* psinfo)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    char tmp_devname[STROAGE_BUFFER_STRINGLEN] = {0};
    char tmp_hookname[STROAGE_BUFFER_STRINGLEN] = {0};
    FILE *fp = NULL;

    if(psinfo == NULL)
    {
        return ERROR;
    }
#ifdef OPENWRT_ARCH
    snprintf(cmd,CMD_MAXLEN,"df -h |grep root");
#else
    snprintf(cmd,CMD_MAXLEN,"df -h |grep -n '^/dev'");
#endif
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp);
    sscanf(recv,"%s %s %s %s %s %s",
        tmp_devname,psinfo->total_info_string,psinfo->used_info_string,
        psinfo->free_info_string,psinfo->used_percent,tmp_hookname);
    STROAGE_INFO_PARAMS(psinfo->total_info_string,psinfo->total_num,psinfo->total_bytetype);
    STROAGE_INFO_PARAMS(psinfo->used_info_string,psinfo->used_num,psinfo->used_bytetype);
    STROAGE_INFO_PARAMS(psinfo->free_info_string,psinfo->free_num,psinfo->free_bytetype);
    psinfo->percent = atoi(psinfo->used_percent);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get_storageinfo: total(%s) free(%s)",psinfo->total_info_string,psinfo->free_info_string);
    return OK;
}

// base64 转换表, 共64个
static const char base64_alphabet[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G',
    'H', 'I', 'J', 'K', 'L', 'M', 'N',
    'O', 'P', 'Q', 'R', 'S', 'T',
    'U', 'V', 'W', 'X', 'Y', 'Z',
    'a', 'b', 'c', 'd', 'e', 'f', 'g',
    'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't',
    'u', 'v', 'w', 'x', 'y', 'z',
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
    '+', '/'};

// 解码时使用
static const unsigned char base64_suffix_map[256] = {
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 253, 255,
    255, 253, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 253, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255,  62, 255, 255, 255,  63,
    52,  53,  54,  55,  56,  57,  58,  59,  60,  61, 255, 255,
    255, 254, 255, 255, 255,   0,   1,   2,   3,   4,   5,   6,
    7,   8,   9,  10,  11,  12,  13,  14,  15,  16,  17,  18,
    19,  20,  21,  22,  23,  24,  25, 255, 255, 255, 255, 255,
    255,  26,  27,  28,  29,  30,  31,  32,  33,  34,  35,  36,
    37,  38,  39,  40,  41,  42,  43,  44,  45,  46,  47,  48,
    49,  50,  51, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,
    255, 255, 255, 255 };

static char cmove_bits(unsigned char src, unsigned lnum, unsigned rnum) {
    src <<= lnum; // src = src << lnum;
    src >>= rnum; // src = src >> rnum;
    return src;
}

int pnr_base64_encode(const char *indata, int inlen, char *outdata, int *outlen) 
{
    int ret = 0; // return value
    if (indata == NULL || inlen == 0) {
        return ret = -1;
    }
    
    int in_len = 0; // 源字符串长度, 如果in_len不是3的倍数, 那么需要补成3的倍数
    int pad_num = 0; // 需要补齐的字符个数, 这样只有2, 1, 0(0的话不需要拼接, )
    if (inlen % 3 != 0) {
        pad_num = 3 - inlen % 3;
    }
    in_len = inlen + pad_num; // 拼接后的长度, 实际编码需要的长度(3的倍数)
    
    int out_len = in_len * 8 / 6; // 编码后的长度
    
    char *p = outdata; // 定义指针指向传出data的首地址
    
    //编码, 长度为调整后的长度, 3字节一组
    for (int i = 0; i < in_len; i+=3) {
        int value = ((*indata >> 2) & 0x3F); // 将indata第一个字符向右移动2bit(丢弃2bit)
        char c = base64_alphabet[value]; // 对应base64转换表的字符
        *p = c; // 将对应字符(编码后字符)赋值给outdata第一字节
        
        //处理最后一组(最后3字节)的数据
        if (i == inlen + pad_num - 3 && pad_num != 0) {
            if(pad_num == 1) {
                *(p + 1) = base64_alphabet[(int)(cmove_bits(*indata, 6, 2) + cmove_bits(*(indata + 1), 0, 4))];
                *(p + 2) = base64_alphabet[(int)cmove_bits(*(indata + 1), 4, 2)];
                *(p + 3) = '=';
            } else if (pad_num == 2) { // 编码后的数据要补两个 '='
                *(p + 1) = base64_alphabet[(int)cmove_bits(*indata, 6, 2)];
                *(p + 2) = '=';
                *(p + 3) = '=';
            }
        } else { // 处理正常的3字节的数据
            *(p + 1) = base64_alphabet[cmove_bits(*indata, 6, 2) + cmove_bits(*(indata + 1), 0, 4)];
            *(p + 2) = base64_alphabet[cmove_bits(*(indata + 1), 4, 2) + cmove_bits(*(indata + 2), 0, 6)];
            *(p + 3) = base64_alphabet[*(indata + 2) & 0x3f];
        }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"base64(0x%2x,0x%2x,0x%2x,0x%2x)(%c%c%c%c)",*p,*(p+1),*(p+2),*(p+3),*p,*(p+1),*(p+2),*(p+3));        
        p += 4;
        indata += 3;
    }
    
    if(outlen != NULL) {
        *outlen = out_len;
    }
    
    return ret;
}


int pnr_base64_decode(const char *indata, int inlen, char *outdata, int *outlen) 
{   
    int ret = 0;
    if (indata == NULL || inlen <= 0 || outdata == NULL || outlen == NULL) {
        return ret = -1;
    }
    if (inlen % 4 != 0) { // 需要解码的数据不是4字节倍数
        inlen --;
        if(inlen % 4 != 0)
        {
            return ret = -2;
        }    
    }
    
    int t = 0, x = 0, y = 0, i = 0;
    unsigned char c = 0;
    int g = 3;
    
    while (indata[x] != 0) {
        // 需要解码的数据对应的ASCII值对应base64_suffix_map的值
        c = base64_suffix_map[indata[x++]];
        if (c == 255) return -1;// 对应的值不在转码表中
        if (c == 253) continue;// 对应的值是换行或者回车
        if (c == 254) { c = 0; g--; }// 对应的值是'='
        t = (t<<6) | c; // 将其依次放入一个int型中占3字节
        if (++y == 4) {
            outdata[i++] = (unsigned char)((t>>16)&0xff);
            if (g > 1) outdata[i++] = (unsigned char)((t>>8)&0xff);
            if (g > 2) outdata[i++] = (unsigned char)(t&0xff);
            y = t = 0;
        }
    }
    if (outlen != NULL) {
        *outlen = i;
    }
    return ret;
}
/**********************************************************************************
  Function:      get_localip_byname
  Description:  根据devname获取ip地址
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_localip_byname(char* devname,char* local_ip)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    FILE *fp = NULL;
    int len = 0;
    if(devname == NULL)
    {
        return ERROR;
    }
#ifdef DEV_ONESPACE
    snprintf(cmd,CMD_MAXLEN,"ifconfig %s | grep \"inet \" | awk '{print $2}'",devname);
#else
    snprintf(cmd,CMD_MAXLEN,"ifconfig %s | grep \"inet addr\" | awk '{print $2}'",devname);
#endif
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_hwaddr_byname cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_hwaddr_byname cmd =%s ret failed",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp); 
    len = strlen(recv);
    if(len > MAC_LEN && len <= IPSTR_MAX_LEN)
    {
        if(recv[len-1] == '\n')
        {
            recv[len-1] = '\0';
            len--;
        }
#ifdef DEV_ONESPACE
        strcpy(local_ip,recv);
#else
        strcpy(local_ip,recv);
#endif
    }
    else
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"get_localip_byname ret(%s)",recv);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      get_hwaddr_byname
  Description:  根据devname获取mac地址
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_hwaddr_byname(char* devname,char* hwaddr_full,char* hwaddr)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    FILE *fp = NULL;
    int i = 0,j = 0;
    int len = 0;
    if(devname == NULL)
    {
        return ERROR;
    }
#ifdef DEV_ONESPACE
    snprintf(cmd,CMD_MAXLEN,"ifconfig %s | grep \"ether\" | awk '{print $2}'",devname);
#else
    snprintf(cmd,CMD_MAXLEN,"ifconfig %s | grep \"HWaddr\" | awk '{print $5}'",devname);
#endif
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_hwaddr_byname cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get_hwaddr_byname cmd =%s ret failed",cmd);
        pclose(fp);
        return ERROR;
    }  
    pclose(fp); 
    len = strlen(recv);
    if(len > MAC_LEN && len <= MACSTR_MAX_LEN)
    {
        if(recv[len-1] == '\n')
        {
            recv[len-1] = '\0';
            len--;
        }
        strcpy(hwaddr_full,recv);
        for(i=0,j=0;i<len;i++)
        {
            if(recv[i] == ':')
            {
                continue;
            }
            else if(recv[i] >= 'a' && recv[i] <= 'z')
            {
                hwaddr[j++] = recv[i] - 32;
            }
            else
            {
                hwaddr[j++] = recv[i];
            }
        }
    }
    else
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"get_hwaddr_byname ret(%s)",recv);
        return ERROR;
    }
    return OK;
}
char g_dev_hwaddr[MACSTR_MAX_LEN] = {0};
char g_dev_hwaddr_full[MACSTR_MAX_LEN] = {0};
char g_dev1_hwaddr[MACSTR_MAX_LEN] = {0};
char g_dev1_hwaddr_full[MACSTR_MAX_LEN] = {0};
/**********************************************************************************
  Function:      pnr_create_usersn
  Description:  生成新的user sn
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_create_usersn(int user_type,int user_index,char* p_usn)
{
    int timestamp = 0;
    if(p_usn == NULL)
    {
        return ERROR;
    }
    if(g_dev_hwaddr[0] == '\0')
    {
        get_hwaddr_byname(DEV_ETH0_KEYNAME,g_dev_hwaddr_full,g_dev_hwaddr);
        //这里是虚拟机测试用
        if(g_dev_hwaddr[0] == '\0')
        {
            get_hwaddr_byname("ens32",g_dev_hwaddr_full,g_dev_hwaddr);
        }
    }
    timestamp = (int)time(NULL);
    snprintf(p_usn,PNR_USN_MAXLEN+1,"%02d%06X%s%012X",user_type,user_index,g_dev_hwaddr,timestamp);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_create_usersn hwaddr(%s) p_usn(%s)",g_dev_hwaddr_full,p_usn);
    return OK;
}
#include "qrencode.h"                                     
#include <png.h>
enum imageType {
	PNG_TYPE,
	PNG32_TYPE,
	EPS_TYPE,
	SVG_TYPE,
	XPM_TYPE,
	ANSI_TYPE,
	ANSI256_TYPE,
	ASCII_TYPE,
	ASCIIi_TYPE,
	UTF8_TYPE,
	ANSIUTF8_TYPE,
	ANSI256UTF8_TYPE,
	UTF8i_TYPE,
	ANSIUTF8i_TYPE
};
#ifndef DEV_ONESPACE
#define INCHES_PER_METER (100.0/2.54)
static void fillRow(unsigned char *row, int num, const unsigned char color[])
{
	int i;

	for(i = 0; i < num; i++) {
		memcpy(row, color, 4);
		row += 4;
	}
}
#endif
static int writePNG(const QRcode *qrcode, const char *outfile, enum imageType type)
{
#ifndef DEV_ONESPACE
    static unsigned char fg_color[4] = {0, 0, 0, 255};
    static unsigned char bg_color[4] = {255, 255, 255, 255};
    int size = 3;
    int margin = 4;
    int dpi = 72;
    static FILE *fp; // avoid clobbering by setjmp.
	png_structp png_ptr;
	png_infop info_ptr;
	png_colorp palette = NULL;
	png_byte alpha_values[2];
	unsigned char *row, *p, *q;
	int x, y, xx, yy, bit;
	int realwidth;

	realwidth = (qrcode->width + margin * 2) * size;
	if(type == PNG_TYPE) {
		row = (unsigned char *)malloc((size_t)((realwidth + 7) / 8));
	} else if(type == PNG32_TYPE) {
		row = (unsigned char *)malloc((size_t)realwidth * 4);
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Internal error.");
        return ERROR;
	}
	if(row == NULL) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to allocate memory.");
        return ERROR;
	}

	if(outfile[0] == '-' && outfile[1] == '\0') {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to create file: %s", outfile);
			perror(NULL);
			return ERROR;
		}
	}

	png_ptr = png_create_write_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
	if(png_ptr == NULL) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to initialize PNG writer.");
        return ERROR;
	}

	info_ptr = png_create_info_struct(png_ptr);
	if(info_ptr == NULL) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to initialize PNG write.");
        return ERROR;
	}

	if(setjmp(png_jmpbuf(png_ptr))) {
		png_destroy_write_struct(&png_ptr, &info_ptr);
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to write PNG image.");
        return ERROR;
	}

	if(type == PNG_TYPE) {
		palette = (png_colorp) malloc(sizeof(png_color) * 2);
		if(palette == NULL) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to allocate memory");
			return ERROR;
		}
		palette[0].red   = fg_color[0];
		palette[0].green = fg_color[1];
		palette[0].blue  = fg_color[2];
		palette[1].red   = bg_color[0];
		palette[1].green = bg_color[1];
		palette[1].blue  = bg_color[2];
		alpha_values[0] = fg_color[3];
		alpha_values[1] = bg_color[3];
		png_set_PLTE(png_ptr, info_ptr, palette, 2);
		png_set_tRNS(png_ptr, info_ptr, alpha_values, 2, NULL);
	}

	png_init_io(png_ptr, fp);
	if(type == PNG_TYPE) {
		png_set_IHDR(png_ptr, info_ptr,
				(unsigned int)realwidth, (unsigned int)realwidth,
				1,
				PNG_COLOR_TYPE_PALETTE,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	} else {
		png_set_IHDR(png_ptr, info_ptr,
				(unsigned int)realwidth, (unsigned int)realwidth,
				8,
				PNG_COLOR_TYPE_RGB_ALPHA,
				PNG_INTERLACE_NONE,
				PNG_COMPRESSION_TYPE_DEFAULT,
				PNG_FILTER_TYPE_DEFAULT);
	}
	png_set_pHYs(png_ptr, info_ptr,
			dpi * INCHES_PER_METER,
			dpi * INCHES_PER_METER,
			PNG_RESOLUTION_METER);
	png_write_info(png_ptr, info_ptr);

	if(type == PNG_TYPE) {
	/* top margin */
		memset(row, 0xff, (size_t)((realwidth + 7) / 8));
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y = 0; y < qrcode->width; y++) {
			memset(row, 0xff, (size_t)((realwidth + 7) / 8));
			q = row;
			q += margin * size / 8;
			bit = 7 - (margin * size % 8);
			for(x = 0; x < qrcode->width; x++) {
				for(xx = 0; xx < size; xx++) {
					*q ^= (*p & 1) << bit;
					bit--;
					if(bit < 0) {
						q++;
						bit = 7;
					}
				}
				p++;
			}
			for(yy = 0; yy < size; yy++) {
				png_write_row(png_ptr, row);
			}
		}
		/* bottom margin */
		memset(row, 0xff, (size_t)((realwidth + 7) / 8));
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	} else {
	/* top margin */
		fillRow(row, realwidth, bg_color);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}

		/* data */
		p = qrcode->data;
		for(y = 0; y < qrcode->width; y++) {
			fillRow(row, realwidth, bg_color);
			for(x = 0; x < qrcode->width; x++) {
				for(xx = 0; xx < size; xx++) {
					if(*p & 1) {
						memcpy(&row[((margin + x) * size + xx) * 4], fg_color, 4);
					}
				}
				p++;
			}
			for(yy = 0; yy < size; yy++) {
				png_write_row(png_ptr, row);
			}
		}
		/* bottom margin */
		fillRow(row, realwidth, bg_color);
		for(y = 0; y < margin * size; y++) {
			png_write_row(png_ptr, row);
		}
	}

	png_write_end(png_ptr, info_ptr);
	png_destroy_write_struct(&png_ptr, &info_ptr);

	fclose(fp);
	free(row);
	free(palette);
#endif
	return 0;
}
static FILE *openFile(const char *outfile)
{
	FILE *fp;

	if(outfile == NULL || (outfile[0] == '-' && outfile[1] == '\0')) {
		fp = stdout;
	} else {
		fp = fopen(outfile, "wb");
		if(fp == NULL) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "Failed to create file: %s", outfile);
			perror(NULL);
			return NULL;
		}
	}

	return fp;
}

static void writeUTF8_margin(FILE* fp, int realwidth, const char* white,
                             const char *reset, const char* full,int margin)
{
	int x, y;

	for (y = 0; y < margin/2; y++) {
		fputs(white, fp);
		for (x = 0; x < realwidth; x++)
			fputs(full, fp);
		fputs(reset, fp);
		fputc('\n', fp);
	}
}

static int writeUTF8(const QRcode *qrcode, const char *outfile, int use_ansi, int invert)
{
	FILE *fp;
	int x, y;
	int realwidth;
	const char *white, *reset;
	const char *empty, *lowhalf, *uphalf, *full;
    int margin = 2;

	empty = " ";
	lowhalf = "\342\226\204";
	uphalf = "\342\226\200";
	full = "\342\226\210";

	if (invert) {
		const char *tmp;

		tmp = empty;
		empty = full;
		full = tmp;

		tmp = lowhalf;
		lowhalf = uphalf;
		uphalf = tmp;
	}

	if (use_ansi){
		if (use_ansi == 2) {
			white = "\033[38;5;231m\033[48;5;16m";
		} else {
			white = "\033[40;37;1m";
		}
		reset = "\033[0m";
	} else {
		white = "";
		reset = "";
	}

	fp = openFile(outfile);

	realwidth = (qrcode->width + margin * 2);

	/* top margin */
	writeUTF8_margin(fp, realwidth, white, reset, full,margin);

	/* data */
	for(y = 0; y < qrcode->width; y += 2) {
		unsigned char *row1, *row2;
		row1 = qrcode->data + y*qrcode->width;
		row2 = row1 + qrcode->width;

		fputs(white, fp);

		for (x = 0; x < margin; x++) {
			fputs(full, fp);
		}

		for (x = 0; x < qrcode->width; x++) {
			if(row1[x] & 1) {
				if(y < qrcode->width - 1 && row2[x] & 1) {
					fputs(empty, fp);
				} else {
					fputs(lowhalf, fp);
				}
			} else if(y < qrcode->width - 1 && row2[x] & 1) {
				fputs(uphalf, fp);
			} else {
				fputs(full, fp);
			}
		}

		for (x = 0; x < margin; x++)
			fputs(full, fp);

		fputs(reset, fp);
		fputc('\n', fp);
	}

	/* bottom margin */
	writeUTF8_margin(fp, realwidth, white, reset, full,margin);

	fclose(fp);

	return 0;
}

/**********************************************************************************
  Function:      pnr_qrcode_create_png
  Description:  生成对应二维码文件
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_qrcode_create_png(char* src_string,char* dst_filename)
{
    int qrversion=1;
    QRcode* pQRC = NULL;
    if(src_string == NULL || dst_filename == NULL)
    {
        return ERROR;
    }
    pQRC = QRcode_encodeString(src_string, qrversion, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (pQRC == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_qrcode_create_png get pQRC FAILED");
        return ERROR;
    }
    
    writePNG(pQRC, dst_filename, PNG_TYPE);
    QRcode_free(pQRC);
    return OK;
}
/**********************************************************************************
  Function:      pnr_qrcode_create_utf8
  Description:  生成对应二维码文件
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_qrcode_create_utf8(char* src_string,char* dst_filename)
{
    int qrversion=1;
    QRcode* pQRC = NULL;
    if(src_string == NULL)
    {
        return ERROR;
    }
    pQRC = QRcode_encodeString(src_string, qrversion, QR_ECLEVEL_H, QR_MODE_8, 1);
    if (pQRC == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_qrcode_create_utf8 get pQRC FAILED");
        return ERROR;
    }
    
    writeUTF8(pQRC, dst_filename,0, 0);
    QRcode_free(pQRC);
    return OK;
}

/**********************************************************************************
  Function:      pnr_qrcode_create_png_bycmd
  Description:  通过命令行生成对应二维码文件
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                 1:调用失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_qrcode_create_png_bycmd(char* src_string,char* dst_filename)
{
    char sys_cmd[CMD_MAXLEN] = {0};

    if(dst_filename == NULL || src_string == NULL)
    {
        return ERROR;
    }
    snprintf(sys_cmd,CMD_MAXLEN,"qrcode_create --ftype png --string %s --file %s",src_string,dst_filename);
    system(sys_cmd);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get srcstring(%s) qrcode_file(%s) ",src_string,dst_filename);
    return OK;
}

/*****************************************************************************
 函 数 名  : get_file_name
 功能描述  : 根据FILE指针获取文件名
 输入参数  : FILE *pf  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int get_file_name(FILE *pf, char *path, int len)
{
	int fd;
	char buf[1024] = {0};

	fd = fileno(pf);
	if (fd == -1) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "bad FILE ptr");
		return -1;
	}

	snprintf(buf, sizeof(buf), "/proc/self/fd/%d", fd);
	if (readlink(buf, path, len - 1) != -1) {
		return 0;
	}

	return -1;
}
/*****************************************************************************
 函 数 名  : get_file_name
 功能描述  : 根据FILE名称获取文件长度
 输入参数  : FILE *pf  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int get_file_size(char* filename) 
{ 
  struct stat statbuf; 
  stat(filename,&statbuf); 
  int size=statbuf.st_size; 
  
  return size; 
}

/*****************************************************************************
 函 数 名  : get_file_content
 功能描述  : 获取文件内容
 输入参数  : char *path  
             char *buf   
             int len     
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月23日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int get_file_content(char *path, char *buf, int len)
{
	FILE *pf = NULL;

	pf = fopen(path, "r");
	if (pf) {
		fread(buf, sizeof(char), len - 1, pf);
		
		fclose(pf);
		return OK;
	}

	return ERROR;
}

/*****************************************************************************
 函 数 名  : get_popen_content
 功能描述  : 获取命令行结果
 输入参数  : char *cmd  
             char *buf  
             int len    
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月23日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int get_popen_content(char *cmd, char *buf, int len)
{
	FILE *pf = NULL;

	pf = popen(cmd, "r");
	if (pf) {
		fread(buf, sizeof(char), len - 1, pf);
		
		pclose(pf);
		return OK;
	}

	return ERROR;
}

/*****************************************************************************
 函 数 名  : pnr_itoa
 功能描述  : 数字转字符串
 输入参数  : 
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
void pnr_itoa (int n,char* pstr) 
{ 
    char *beg = pstr;
    int sign;
    if ((sign = n) < 0) n = -n;
 
    do{
        *pstr++ = '0' + n % 10;
    }while((n /= 10) > 0);
 
    if (sign < 0) *pstr++ = '-';
 
    *pstr = '\0';
 
    char *end = pstr - 1;
    while(beg < end){
        char tmp = *beg;
        *beg++ = *end;
        *end-- = tmp;
    }
}

int dev_hwaddr_init(void)
{
    if(g_dev_hwaddr[0] == '\0')
    {
        get_hwaddr_byname(DEV_ETH0_KEYNAME,g_dev_hwaddr_full,g_dev_hwaddr);
        if(g_pnrdevtype == PNR_DEV_TYPE_ONESPACE)
        {
            get_hwaddr_byname(DEV_ETH1_KEYNAME,g_dev1_hwaddr_full,g_dev1_hwaddr);
        }
        //这里是虚拟机测试用
        if(g_dev_hwaddr[0] == '\0')
        {
            get_hwaddr_byname("ens32",g_dev_hwaddr_full,g_dev_hwaddr);
        }
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"dev_hwaddr_init(%s)(%s)",g_dev_hwaddr,g_dev_hwaddr_full);
    return OK;
}

// BKDR Hash Function
unsigned int pnr_BKDRHash(char *str)
{
    unsigned int seed = 131; // 31 131 1313 13131 131313 etc..
    unsigned int hash = 0;
 
    while (*str)
    {
        hash = hash * seed + (*str++);
    }
 
    return (hash & 0x7FFFFFFF);
}
int pnr_uidhash_get(int u_index,int f_num,char* tox_id,unsigned int* hashnum,char* p_ret_hashstr)
{
    if(tox_id == NULL || hashnum == NULL || p_ret_hashstr == NULL)
    {
        return ERROR;
    }
    if(u_index > PNR_IMUSER_MAXNUM || f_num > PNR_IMUSER_FRIENDS_MAXNUM)
    {
        return ERROR;
    }
    *hashnum = pnr_BKDRHash(tox_id);
    snprintf(p_ret_hashstr,PNR_USER_HASHID_MAXLEN,"%03d%03d%08X",
        (u_index&0xFF),(f_num&0xFF),*hashnum);
    return OK;
}
/*将大写字母转换成小写字母*/  
int pnr_tolower(int c)  
{  
    if (c >= 'A' && c <= 'Z')  
    {  
        return c + 'a' - 'A';  
    }  
    else  
    {  
        return c;  
    }  
}  

//将十六进制的字符串转换成整数  
int pnr_htoi(char* s)  
{  
    int i = 0;  
    int n = 0;  
    if (s[0] == '0' && (s[1]=='x' || s[1]=='X'))  
    {  
        i = 2;  
    }  
    else  
    {  
        i = 0;  
    }  
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >='A' && s[i] <= 'Z');++i)  
    {  
        if (pnr_tolower(s[i]) > '9')  
        {  
            n = 16 * n + (10 + pnr_tolower(s[i]) - 'a');  
        }  
        else  
        {  
            n = 16 * n + (pnr_tolower(s[i]) - '0');  
        }  
    }  
    return n;  
}  
/*****************************************************************************
 函 数 名  : pnr_sign_check
 功能描述  : 签名验证
 输入参数  : 
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_sign_check(char* sign,int sign_len,char* pubkey,int base64encode_flag)
{
    unsigned char sign_bin[PNR_RSA_KEY_MAXLEN+1] = {0};
    unsigned char key_bin[PNR_RSA_KEY_MAXLEN+1] = {0};
    unsigned char decode_bin[PNR_RSA_KEY_MAXLEN+1] = {0};
    unsigned long long sign_binlen = 0;
    unsigned long long key_binlen = 0;
    unsigned long long decode_len = 0;
    
    if(sign == NULL || pubkey == NULL || sign_len > PNR_RSA_KEY_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_sign_check input err");
        return ERROR;
    }
    if(base64encode_flag == TRUE)
    {
        pnr_base64_decode(sign,sign_len,(char*)sign_bin,(int*)&sign_binlen);
    }
    else
    {
        strcpy((char*)sign_bin,sign);
        sign_binlen = (unsigned long long)sign_len;
    }
    pnr_base64_decode(pubkey,strlen(pubkey),(char*)key_bin,(int*)&key_binlen);
    if(crypto_sign_open(decode_bin,&decode_len,sign_bin,sign_binlen,key_bin) == OK)
    {
        return OK;
    }
    return ERROR;
}
/*****************************************************************************
 函 数 名  : pnr_check_process_byname
 功能描述  : 根据进程名称检测进程是否在
 输入参数  : 
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_check_process_byname(char* pname,int* pid)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    
    FILE *fp = NULL;

    if(pname == NULL || pid == NULL)
    {
        return ERROR;
    }
    if(g_pnrdevtype == PNR_DEV_TYPE_ONESPACE || g_pnrdevtype == PNR_DEV_TYPE_X86SERVER)
    {
        snprintf(cmd,CMD_MAXLEN,"ps -ef |grep \"%s\"|grep -v grep | awk '{print $2}' ",pname);
    }
    else
    {
        snprintf(cmd,CMD_MAXLEN,"ps |grep \"%s\"|grep -v grep | awk '{print $3}'",pname);
    }
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
        return ERROR;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
        pclose(fp);
        return ERROR;
    }  
    *pid = atoi(recv);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_check_process_byname: cmd(%s) get pid(%d)",cmd,*pid);
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_check_frp_connstatus
 功能描述  : 检测frp连接是否正常
 输入参数  : 
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_check_frp_connstatus(void)
{
    char cmd[CMD_MAXLEN] = {0};
    char recv[CMD_MAXLEN] = {0};
    
    FILE *fp = NULL;
    snprintf(cmd,CMD_MAXLEN,"tail -n 1 /tmp/frp.log ");
    if (!(fp = popen(cmd, "r"))) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"popen cmd(%s) failed",cmd);
        return FALSE;
    }
    if (fgets(recv,CMD_MAXLEN,fp) <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"failed cmd =%s",cmd);
        pclose(fp);
        return FALSE;
    }  
    if(strstr(recv,PNR_FRPC_CONNSTATUS_OKKEY) != NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"frp connect ok");
        return TRUE;
    }
    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"frp connect faile(%s)",recv);
    return FALSE;
}
/*****************************************************************************
 函 数 名  : pnr_stristr
 功能描述  : 不care大小写的字符串查找
 输入参数  : 
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
char* pnr_stristr (const char * str1,const char * str2)
{
    char *cp = (char *) str1;
    char *s1, *s2;

    if ( !*str2 )
    {
        return((char *)str1);
    }

    while (*cp)
    {
        s1 = cp;
        s2 = (char *) str2;
        while (*s1 && *s2)
        {
            char ch1=*s1,ch2=*s2;
            if (isascii(*s1) && isupper(*s1) ) 
                ch1 = _tolower(*s1);
            if (isascii(*s2) && isupper(*s2) ) 
                ch2 = _tolower(*s2);

            if(ch1-ch2==0) 
                s1++, s2++;
            else 
                break;
        }

        if (!*s2)
            return(cp);
        cp++;
    }
    return(NULL);
}

