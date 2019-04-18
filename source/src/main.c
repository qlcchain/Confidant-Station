/*************************************************************************
 *
 *  main文件
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
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif
	 
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
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/select.h>
#include <semaphore.h> 
#include <stdarg.h>
#include <pthread.h>
#include <signal.h>
#include <time.h>
#include <sys/param.h>
#include <getopt.h>
#include <sys/socket.h>
#include <locale.h>
#include <errno.h> 
#include <sqlite3.h>
#include <sys/time.h>
#include <sys/resource.h>

#include "cJSON.h"
#include "sql_db.h"
#include "common_lib.h"
#include "pn_imserver.h"
#include "version.h"
#include "tox_seg_msg.h"

static struct option long_opts[] = {
    {"help", no_argument, 0, 'h'},
    {"type", required_argument, 0, 't'},
    {"showqrcode", required_argument, 0, 's'},
    {"encrypt", required_argument, 0, 'e'},
    {"version", no_argument, 0, 'v'},
    {NULL, no_argument, NULL, 0},
};

const char *opts_str = "4bdeou:t:s:h:v:p:P:T:";
struct arg_opts_struct g_arg_opts;
char g_post_ret_buf[POST_RET_MAX_LEN] = {0};
extern sqlite3 *g_db_handle;
extern sqlite3 *g_friendsdb_handle;
extern sqlite3 *g_msglogdb_handle[PNR_IMUSER_MAXNUM+1];
extern struct im_user_array_struct g_imusr_array;
extern const char *data_file_name;
extern Tox *qlinkNode;
extern sqlite3 *g_msgcachedb_handle[PNR_IMUSER_MAXNUM+1];
extern char g_devadmin_loginkey[PNR_LOGINKEY_MAXLEN+1];
extern int g_format_reboot_time;
extern char g_dev_nickname[PNR_USERNAME_MAXLEN+1];
extern int g_pnrdevtype;
void *server_discovery_thread(void *args);
int im_debug_imcmd_deal(char* pcmd);

/*************************************************************************
 *
 * Function name: set_default_opts
 * 
 * Instruction: 设置默认启动参数
 * 
 * INPUT:none
 * 
 * 
 * OUPUT: none
 *
 *************************************************************************/
static void set_default_opts(void)
{
    memset(&g_arg_opts, 0, sizeof(g_arg_opts));
    /* set any non-zero defaults here*/
}
void print_usage(void)
{
    printf("command for example:\n");
    printf("\t pnr_server --showqrcode  XXX\n");
    printf("\t pnr_server --encrypt  XXX\n");
	printf("\t pnr_server --version\n");
    printf("\t pnr_server\n"); 
    printf("\t pnr_server -h\n");
    printf("\n");
}
void print_version(void)
{
    printf("version:%s.%s.%s\n"
		"build:%s ~ %s\n",
        PNR_SERVER_TOPVERSION,
        PNR_SERVER_MIDVERSION,
        PNR_SERVER_LOWVERSION,
        PNR_SERVER_BUILD_TIME,
	PNR_SERVER_BUILD_HASH);
}

/**********************************************************************************
  Function:      parse_args
  Description:   参数解析函数
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
static void parse_args(int argc, char *argv[])
{
    set_default_opts();

    int opt, indexptr;
    //long int port = 0;

    while ((opt = getopt_long(argc, argv, opts_str, long_opts, &indexptr)) != -1) 
    {
        switch (opt) 
        {
            case 'v':
    			print_version();
    			exit(EXIT_SUCCESS);
            case 's':
                account_qrcode_show(optarg);
    			exit(EXIT_SUCCESS);
            case 'e':
                pnr_encrypt_show(optarg,TRUE);
    			exit(EXIT_SUCCESS);
    		case 'h':
    		default:
    			print_usage();
    			exit(EXIT_SUCCESS);
                break;
        }
    }
}
/**********************************************************************************
  Function:      signal_init
  Description:  信号量屏蔽
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
int signal_init(void)
{ 
    //忽略终端I/O信号，STOP信号
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
 
    //改变工作目录，使得进程不与任何文件系统联系
    chdir("/tmp");
 
    //将文件当时创建屏蔽字设置为0
    umask(0);
 
    //忽略SIGCHLD信号
    signal(SIGCHLD,SIG_IGN); 
    return 0;
}
/**********************************************************************************
  Function:      init_daemon
  Description:  切换为后台进程
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
int init_daemon(void)
{ 
    int pid; 
    int i; 
 
    //忽略终端I/O信号，STOP信号
    signal(SIGTTOU,SIG_IGN);
    signal(SIGTTIN,SIG_IGN);
    signal(SIGTSTP,SIG_IGN);
    signal(SIGHUP,SIG_IGN);
    
    pid = fork();
    if(pid > 0) {
        exit(0); //结束父进程，使得子进程成为后台进程
    }
    else if(pid < 0) { 
        return -1;
    }
 
    //建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端
    setsid();
 
    //再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端
    pid=fork();
    if( pid > 0) {
        exit(0);
    }
    else if( pid< 0) {
        return -1;
    }
 
    //关闭所有从父进程继承的不再需要的文件描述符
    for(i=0;i< NOFILE;close(i++));
 
    //改变工作目录，使得进程不与任何文件系统联系
    chdir("/tmp");
 
    //将文件当时创建屏蔽字设置为0
    umask(0);
 
    //忽略SIGCHLD信号
    signal(SIGCHLD,SIG_IGN); 
    
    return 0;
}

/**********************************************************************************
  Function:      daemon_exists
  Description:  检测并生成pid文件
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
int daemon_exists(void)
{
	int fd;
	struct flock lock;
	char buffer[32];

	fd = open(DEAMON_PIDFILE, O_RDWR | O_CREAT, S_IRWXU | S_IRWXG | S_IRWXO);
	if (fd < 0) {
		return 0;
	}

	lock.l_type = F_WRLCK;
	lock.l_whence = SEEK_SET;
	lock.l_start = 0;
	lock.l_len = 0;

	if (fcntl(fd, F_SETLK, &lock) != 0) {
		close(fd);
		return 1;
	}

	ftruncate(fd, 0);
	snprintf(buffer, sizeof(buffer), "%d", getpid());
	write(fd, buffer, strlen(buffer));
	return 0;
}
/**********************************************************************************
  Function:      qlv_daemon_init
  Description:  qlv守护进程初始化
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
int daemon_init(void)
{
	int8* errMsg = NULL;
    struct db_string_ret db_ret;
	char sql_cmd[SQL_CMD_LEN] = {0};
	struct rlimit resource = {65535, 65535};

    //建立通信管道
    unlink(DAEMON_FIFONAME);
    if (mkfifo(DAEMON_FIFONAME, 0777) == -1)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"mkfifo error %s", strerror(errno));
		return ERROR;
    }

	setrlimit(RLIMIT_NOFILE, &resource);
    //这里如果是onespace，需要先执行下rngd，要不然 sodium_init会很慢
    if(g_pnrdevtype == PNR_DEV_TYPE_ONESPACE)
    {
        system("/usr/bin/rngd -r/dev/urandom");
        system("echo 180 > /proc/sys/net/ipv4/netfilter/ip_conntrack_udp_timeout");
    }

    //建立文件目录
    if(access(DAEMON_PNR_TOP_DIR,F_OK) != OK)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"mkdir -p %s",DAEMON_PNR_TOP_DIR);
        system(sql_cmd);
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_cmd (%s)",sql_cmd);
    }  
    /* 忽略EPIPE信号，不然程序会异常退出 */ 
    signal(SIGPIPE, SIG_IGN); 
    
    //检查数据库
    if(sql_db_check() != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_db_check error %s", strerror(errno));
		return ERROR;
    }
    //获取当前配置

    //im_server初始化
    if (im_server_init() != OK) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_server_init failed");
		return ERROR;
	}
	snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_IMUSER_MAXNUM_KEYWORDK);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&g_imusr_array.max_user_num,&errMsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get imuser_maxnum failed");
		sqlite3_free(errMsg);
		return ERROR;
	}
    db_ret.buf_len = PNR_LOGINKEY_MAXLEN;
    db_ret.pbuf = g_devadmin_loginkey;
	snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_DEVLOGINEKEY_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_singstr_result,&db_ret,&errMsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get dev_loginkey failed");
		sqlite3_free(errMsg);
		return ERROR;
	}
    db_ret.buf_len = PNR_USERNAME_MAXLEN;
    db_ret.pbuf = g_dev_nickname;
	snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_DEVNAME_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_singstr_result,&db_ret,&errMsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get g_dev_nickname failed");
		sqlite3_free(errMsg);
		return ERROR;
	}
    dev_hwaddr_init();
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get g_imusr_maxnum %d,cur_num %d,g_dev_nickname(%d:%s)",
        g_imusr_array.max_user_num,g_imusr_array.cur_user_num,db_ret.buf_len,g_dev_nickname);
    return OK;
}

/**********************************************************************************
  Function:      test_daemon
  Description:  守护进程，
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
static void *test_daemon(void *para)
{

	return NULL;
}
/**********************************************************************************
  Function:      tox_daemon
  Description:  tox守护进程，负责基础的p2p网络组建，接收winq的消息
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
static void *tox_daemon(void *para)
{
    CreatedP2PNetwork();
	return NULL;
}
/**********************************************************************************
  Function:      imserver_daemon
  Description:  im_server守护进程，负责与app的通信
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
static void *imserver_daemon(void *para)
{
    im_server_main();
	return NULL;
}

/**********************************************************************************
  Function:      monstat_daemon
  Description:  状态检测守护进程，负责系统整体状态检测
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
static void *monstat_daemon(void *para)
{
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"monstat_daemon in ");
    while(1)
    {
        get_meminfo();
        sleep(SYSINFO_CHECK_CYCLE);
    }
	return NULL;
}
/**********************************************************************************
  Function:      heartbeat_daemon
  Description:  心跳守护进程，负责维系心跳
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
static void *heartbeat_daemon(void *para)
{
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"heartbeat_daemon in ");
    while(1)
    {
        //Heartbeat();
        sleep(HEARTBEAT_CYCLE);
    }
	return NULL;
}
/**********************************************************************************
  Function:      imuser_heartbeat_daemon
  Description:  im用户心跳守护进程
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
static void *imuser_heartbeat_daemon(void *para)
{
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"heartbeat_daemon in ");
    while(1)
    {
        imuser_heartbeat_deal();
        sleep(IMUSER_HEARTBEAT_CYCLE);
    }
	return NULL;
}

/*****************************************************************************
 函 数 名  : im_send_msg_daemon
 功能描述  : 处理待发送消息
 输入参数  : void *para  
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月16日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void *im_send_msg_daemon(void *para)
{
	int *direction = (int *)para;
	
	while (1) {
        im_send_msg_deal(*direction);
        usleep(50000);
    }
	
	return NULL;
}

/**********************************************************************************
  Function:      msg_deal
  Description:  上报消息处理入口
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2012-03-07
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
void msg_deal(char * pbuf,int msg_len)
{
	int msg_type = 0;
	msg_type = atoi(pbuf);
	pbuf = strchr(pbuf,0x20);
	if(pbuf == NULL)
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad msg_type param %d",pbuf);  
		return;
	}
	pbuf ++;
	msg_len -= 2;
	DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"msg_deal len(%d) msg_type(%d) msg(%s)",msg_len,msg_type,pbuf); 
	switch(msg_type)
	{
	    case PNR_DEBUGCMD_SHOW_GLOBALINFO:
            im_global_info_show(pbuf);
            break;
        case PNR_DEBUGCMD_DATAFILE_BASE64_CHANGED:
            im_datafile_base64_change_cmddeal(pbuf);
            break;
        case PNR_DEBUGCMD_ACCOUNT_QRCODE_GET:
            im_account_qrcode_get_cmddeal(pbuf);
            break;
        case PNR_DEBUGCMD_DEBUG_IMCMD:
            im_debug_imcmd_deal(pbuf);
            break;
        case PNR_DEBUGCMD_PUSHNEWMSG_NOTICE:
            im_debug_pushnewnotice_deal(pbuf);
            break;
        //动态设置某些系统功能的开关
        case PNR_DEBUGCMD_SET_FUNCENABLE:
            im_debug_setfunc_deal(pbuf);
            break;
        //使能模拟用户测试
        case PNR_DEBUGCMD_SET_SIMULATION:
            im_simulation_setfunc_deal(pbuf);
            break;
        case PNR_DEBUGCMD_DEVINFO_REG:
            post_devinfo_upload_once(pbuf);
            break;
		default:
			DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad msg_type param %d",msg_type);  
			break;
	}
	return;
}

/**********************************************************************************
  Function:      fifo_msg_handle
  Description:  消息处理
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others:

  History: 1. Date:2012-03-07
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
static int fifo_msg_handle(void)
{
    int fpipe;
    char line[BUF_LINE_MAX_LEN] = {0};
    char* pbuf;
	int line_len = 0;
    char* p_end = NULL;
	
	fpipe = open(DAEMON_FIFONAME, O_RDONLY);
	//监听管道
	while(1)
    {	
    	line_len = read(fpipe, line, BUF_LINE_MAX_LEN);
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"fifo_msg_handle read ret(%d)",line_len);  
        //消息结构体是类似 "3 XXXX"
		if(line_len >= 3)
		{
			if(line[line_len-1] == '\n')
			{
				line[line_len-1] = 0;
				line_len = line_len-1;
			}
			//DEBUG_PRINT(DEBUG_LEVEL_INFO,"fifo_msg_handle %d (%s)",line_len,line);  
			pbuf = &line[0];
			p_end = NULL;
			p_end = strchr(pbuf,'\n');
			if(p_end != NULL)
			{
				//DEBUG_PRINT(DEBUG_LEVEL_INFO,"###########################################"); 
				//DEBUG_PRINT(DEBUG_LEVEL_INFO,"get len(%d) msg(%s)",line_len,pbuf); 
				while(1)
				{
					p_end[0] = 0;
					msg_deal(pbuf,p_end-pbuf);
					pbuf = p_end +1;
					p_end = NULL;
					p_end = strchr(pbuf,'\n');
					if(p_end == NULL)
					{
						msg_deal(pbuf,&line[line_len]-pbuf);
						break;
					}
				}
			}
			else
			{
				msg_deal(pbuf,line_len);
			}
            close(fpipe);
            fpipe = open(DAEMON_FIFONAME, O_RDONLY);
		}
		else
		{
    		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad return (%d)",line_len); 
		    usleep(500);
            close(fpipe);
            fpipe = open(DAEMON_FIFONAME, O_RDONLY);
			continue;
		}
		memset(line,0,BUF_LINE_MAX_LEN);
	}
	
	close(fpipe);
    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"fifo exit");  
	return OK;
}

/*****************************************************************************
 函 数 名  : cron_thread
 功能描述  : 定时任务线程
 输入参数  : void arg  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void *cron_thread(void *para)
{
	char sql[1024];
	int8 *err = NULL;
	int deadtime, nowtime;
	int i = 0;
	
	while (1) {
		nowtime = time(NULL);

		for (i = 1; i <= PNR_IMUSER_MAXNUM; i++) {
			if (g_msgcachedb_handle[i] && (nowtime % 60 == 0)) {
				memset(sql, 0, sizeof(sql));
				deadtime = nowtime - 60;
				
				//use len as insert time
				snprintf(sql, sizeof(sql), "delete from msg_tbl where fromid='' and len < %d;", deadtime);

				if (sqlite3_exec(g_msgcachedb_handle[i], sql, 0, 0, &err)) {
			        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql, err);
			        sqlite3_free(err);
			    }
			}
		}

		if (g_format_reboot_time > 0 && nowtime >= g_format_reboot_time)
			system("sync;/opt/bin/umounthd.sh;reboot");
		
		sleep(1);
	}
}

/**********************************************************************************
  Function:      main
  Description:  程序主入口函数，负责输入参数解析，启动任务等
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
int32 main(int argc,char *argv[])
{
    pthread_t monstat_tid;
    pthread_t imserver_tid;
    pthread_t maintox_tid;
    pthread_t imuser_heartbeat_tid;
	pthread_t tid;
	int i = 0;

	/*调试开关*/
    DEBUG_INIT(LOG_PATH);
    DEBUG_LEVEL(DEBUG_LEVEL_INFO);
	parse_args(argc, argv);
    //路由器上用proc脚本切换到后台
#ifdef OPENWRT_ARCH
    signal_init();
#else
    init_daemon();
#endif
    if (daemon_exists()) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "main exist");
        exit(1);
    }

	if (daemon_init()) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "init failed");
        exit(1);
	}

    //读取配置信息
    /*建立消息队列*/
    
    /*启动主tox进程，建立P2P网络*/
	if (pthread_create(&maintox_tid, NULL, tox_daemon,NULL) != OK)
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create tox_daemon failed");
        goto out;
	}
	
     /*启动monitor_stat进程，监控系统资源使用情况*/
    if (pthread_create(&monstat_tid, NULL, monstat_daemon, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create monstat_daemon failed");
        goto out;
	}   

    //启动im server进程
    if (pthread_create(&imserver_tid, NULL, imserver_daemon, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create imserver_daemon failed");
        goto out;
	}
	
    //启动im heartbeat进程
    if (pthread_create(&imuser_heartbeat_tid, NULL, imuser_heartbeat_daemon, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create imuser_heartbeat_daemon failed");
        goto out;
	}

	//启动消息发送进程
	for (i = 0; i < 2; i++) {
		if (pthread_create(&tid, NULL, im_send_msg_daemon, &i) != 0) 
	    {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create imuser_heartbeat_daemon failed");
	        goto out;
		}
	}

    //服务器发现消息
    if (pthread_create(&tid, NULL, server_discovery_thread, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create server discovery failed");
        goto out;
	}

    //pnr_qrcode_create_png_bycmd("111223334455","/tmp/test1.png");

	//tox分片消息清理
    if (pthread_create(&tid, NULL, tox_seg_msg_flush, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create server discovery failed");
        goto out;
	}

	//定时任务
	if (pthread_create(&tid, NULL, cron_thread, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create cron failed");
        goto out;
	}
    //设备注册任务
    if(g_pnrdevtype == PNR_DEV_TYPE_ONESPACE)
    {
	    if (pthread_create(&tid, NULL,post_devinfo_upload_task, NULL) != 0) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create post_devinfo_upload_task failed");
            goto out;
        }
    }    
    //消息推送轮询任务
    if (pthread_create(&tid, NULL,post_newmsgs_loop_task, NULL) != 0) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "pthread_create post_newmsgs_loop_task failed");
        goto out;
    }
    fifo_msg_handle();
    while(1)
    {
        sleep(1);
    }

out:
	sqlite3_close(g_db_handle);
	sqlite3_close(g_friendsdb_handle);
    return OK;
}

