#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "common_lib.h"
#include <errno.h>
#include <openssl/aes.h>
#include <time.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <unistd.h>
#include "common_lib.h"
#include "base64.h"
#include "pn_imserver.h"

#define LISTEN_PORT 18000
#define AES_KEY_STR "slph$%*&^@-78231"
#define AES_IV_STR "AABBCCDDEEFFGGHH"
#define TEXT_BUF_LEN 128

extern struct im_user_struct g_daemon_tox;

/*****************************************************************************
 函 数 名  : is_valid_ip
 功能描述  : 检测是否有效ip地址
 输入参数  : char *ip  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月2日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
bool is_valid_ip(char *ip)
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip, &(sa.sin_addr));
    return result != 0;
}

/*****************************************************************************
 函 数 名  : get_dev_ip
 功能描述  : 获取网口ip地址
 输入参数  : char *devname  
             char *ip       
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月7日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static int get_dev_ip(char *devname, char *ip)
{
    int sock_fd;
    struct ifreq ifr;
 
    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)     
		return -1;
 
    strcpy(ifr.ifr_name, devname);
    
    if (ioctl(sock_fd, SIOCGIFADDR, &ifr) < 0) {
        close(sock_fd);
        return -1;
    }

    snprintf(ip, 16, "%s", inet_ntoa(((struct sockaddr_in*)&ifr.ifr_addr)->sin_addr));

    close(sock_fd);
    return -1;
}

/*****************************************************************************
 函 数 名  : get_dev_mac
 功能描述  : 获取接口MAC地址
 输入参数  : char *devname  
             char *mac      
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月18日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static int get_dev_mac(char *devname, char *mac)
{
	int sock_fd;
    struct ifreq ifr;
	int i = 0;
 
    sock_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (sock_fd < 0)     
		return -1;
 
    strcpy(ifr.ifr_name, devname);
    
    if (ioctl(sock_fd, SIOCGIFHWADDR, &ifr) < 0) {
        close(sock_fd);
        return -1;
    }
	
	for (i = 0; i < 6; ++i) {
		sprintf(mac + 3 * i, "%02x:", (unsigned char)ifr.ifr_hwaddr.sa_data[i]);
	}

	mac[17] = 0;
	
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "mac~~%s", mac);
    close(sock_fd);
    return -1;
}

/*****************************************************************************
 函 数 名  : get_encrypt_ipinfo
 功能描述  : 获取加密后的wan接口地址信息
 输入参数  : char *devname  
             char *ip       
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月7日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int get_encrypt_ipinfo(char *out)
{
	char iface[16] = {0};
	AES_KEY ctx;
    char text[TEXT_BUF_LEN] = {0};
    char textenc[TEXT_BUF_LEN] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    unsigned char padpay = 0;
	int padlen = 0, slen = 0;
	char *ret = NULL;
	int i = 0;

#ifdef OPENWRT_ARCH
	ret = uci_get_config_value("network", "interface", "wan", "ifname", iface, 15, "/etc/config");
#elif DEV_ONESPACE
    ret = strcpy(iface, "eth0");
#else
    return 0;
#endif
	if (ret) {
		get_dev_ip(iface, text);
		if (!is_valid_ip(text)) {
#ifdef DEV_ONESPACE
            ret = strcpy(iface, "eth1");
            get_dev_ip(iface, text);
            if (!is_valid_ip(text)) {
    			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get wandev(%s) ip err(%s)!\n", iface,text);
    			return -1;
    		}
#else
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get wandev(%s) ip err(%s)!\n", iface,text);
                    return -1;
#endif
        }

		strncat(text, ";", TEXT_BUF_LEN - strlen(text) - 1);
        strncat(text, g_daemon_tox.user_toxid, TEXT_BUF_LEN - strlen(text) - 1);
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "discovey ip:%s", text);
		
        slen = strlen(text);
        if ((slen % AES_BLOCK_SIZE) != 0) {
            padlen = slen;
            padpay = AES_BLOCK_SIZE - (padlen % AES_BLOCK_SIZE);
            slen = ((slen / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;

            for (i = padlen; i < slen; i++)
                text[i] = padpay;
        }

		memcpy(iv, AES_IV_STR, AES_BLOCK_SIZE);
        AES_set_encrypt_key((unsigned char *)AES_KEY_STR, 128, &ctx);
        AES_cbc_encrypt((unsigned char *)text, (unsigned char *)textenc, 
            strlen(text), &ctx, iv, AES_ENCRYPT);
        base64_encode(textenc, slen, out);

		return 0;
	} else {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get wan iface name err!\n");
		return -1;
	}
}
extern int g_pnrdevtype;
/*****************************************************************************
 函 数 名  : server_discovery_thread
 功能描述  : 服务器发现线程
 输入参数  : void *args  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月7日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void *server_discovery_thread(void *args)
{
	int sock = -1;
	int ret = 0;
    struct sockaddr_in local_addr;
	struct sockaddr_in source_addr;
    AES_KEY ctx;
    char text[TEXT_BUF_LEN] = {0};
	char mac[32] = {0};
	char mac1[32] = {0};
    char textenc[TEXT_BUF_LEN] = {0};
    char textb64[TEXT_BUF_LEN * 2] = {0};
	char textb64send[TEXT_BUF_LEN * 2] = {0};
    unsigned char iv[AES_BLOCK_SIZE] = {0};
    struct timeval timeout = {0, 10000};
	int ifgetip = 0;
	int type = 0;
	socklen_t addrlen;
    int opt=SO_REUSEADDR;
    
	sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock == -1) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "create socket err!(%d)\n", errno);
        return NULL;
    }
    setsockopt(sock,SOL_SOCKET,SO_REUSEADDR,&opt,sizeof(opt));
	memset(&local_addr, 0, sizeof(struct sockaddr_in));
    local_addr.sin_family = AF_INET;
    local_addr.sin_addr.s_addr = htonl(INADDR_ANY);
	local_addr.sin_port = htons(LISTEN_PORT);

    ret = bind(sock, (struct sockaddr *)&local_addr, sizeof(struct sockaddr));
	if (ret == -1) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "bind socket err!(%d)\n", errno);
        return NULL;
	}
	setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (char *)&timeout, sizeof(struct timeval)); 
    while (1) {
		if (!g_daemon_tox.user_toxid[0]) {
            sleep(1);
            continue;
        }

		if (!ifgetip) {
			get_dev_mac("eth0", mac);
            if(g_pnrdevtype == PNR_DEV_TYPE_ONESPACE)
            {
			    get_dev_mac("eth1", mac1);
			}
            ret = get_encrypt_ipinfo(textb64send);
			if (ret < 0) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get encrypt ipinfo err!\n");
				sleep(1);
				continue;
			}
			ifgetip = 1;
		}

		memset(textb64, 0, TEXT_BUF_LEN * 2);
		memset(&source_addr, 0, sizeof(struct sockaddr_in));
		addrlen = sizeof(struct sockaddr);
		ret = recvfrom(sock, textb64, sizeof(textb64), 0, (struct sockaddr *)&source_addr, &addrlen);
		if (ret > 0) {
			if (!memcmp(textb64, "QLC", 3)) {
				type = 1;
			} else if (!memcmp(textb64, "MAC", 3)) {
				type = 2;
			} else {
			    DEBUG_PRINT(DEBUG_LEVEL_INFO,"rcv(%s) continue",textb64);
				continue;
			}
			
			memset(text, 0, TEXT_BUF_LEN);
		    memset(textenc, 0, TEXT_BUF_LEN);

			int encsize = 0;
			encsize = base64_decode(&textb64[3], textenc);

			memcpy(iv, AES_IV_STR, AES_BLOCK_SIZE);
    		AES_set_decrypt_key((unsigned char *)AES_KEY_STR, 128, &ctx);
    		AES_cbc_encrypt((unsigned char *)textenc, (unsigned char *)text, encsize, &ctx, iv, AES_DECRYPT);

			switch (type) {
			case 1:
				if (strncasecmp(text, g_daemon_tox.user_toxid, TOX_ID_STR_LEN)) {
					DEBUG_PRINT(DEBUG_LEVEL_INFO, "rcv tox(%s)", text);
					continue;
				}
				break;

			case 2:
                if(g_pnrdevtype == PNR_DEV_TYPE_ONESPACE)
                {
                    if ((strncasecmp(text, mac1, 17) != OK) && (strncasecmp(text, mac, 17) != OK))
                    {
    					DEBUG_PRINT(DEBUG_LEVEL_INFO, "rcv mac(%s)", text);
    					continue;
				    }
                }
                else
                {
                    if(strncasecmp(text, mac, 17) != OK)
                    {
    					DEBUG_PRINT(DEBUG_LEVEL_INFO, "rcv mac(%s)", text);
    					continue;
				    }
                }
				break;
			}
			
			ret = sendto(sock, textb64send, strlen(textb64send), 0, (struct sockaddr*)&source_addr, sizeof(source_addr));
            if (ret < 0) {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sendto err!(%s:%d)(%d)", inet_ntoa(source_addr.sin_addr), source_addr.sin_port, errno);
            }
		}
        else
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "recvfrom err!(%d)(%d)", ret,errno);
        }        
    }

    return NULL;
}

