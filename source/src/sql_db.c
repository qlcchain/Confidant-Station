#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <curl/curl.h>
#include <syslog.h>
#include "common_lib.h"
#include "sql_db.h"
#include "pn_imserver.h"

sqlite3 *g_db_handle = NULL;
sqlite3 *g_friendsdb_handle = NULL;
sqlite3 *g_msglogdb_handle[PNR_IMUSER_MAXNUM+1] = {0};
sqlite3 *g_msgcachedb_handle[PNR_IMUSER_MAXNUM+1] = {0};
sqlite3 *g_groupdb_handle = NULL;
extern struct im_user_array_struct g_imusr_array;
extern struct lws_cache_msg_struct g_lws_cache_msglist[PNR_IMUSER_MAXNUM+1];
extern pthread_mutex_t lws_cache_msglock[PNR_IMUSER_MAXNUM+1];
extern struct pnr_account_array_struct g_account_array;
extern struct pnr_tox_datafile_struct g_tox_datafile[PNR_IMUSER_MAXNUM+1];
extern File_Sender file_senders[PNR_IMUSER_MAXNUM+1][NUM_FILE_SENDERS];
extern File_Rcv file_rcv[PNR_IMUSER_MAXNUM+1][NUM_FILE_RCV];
extern Tox* g_tox_linknode[PNR_IMUSER_MAXNUM+1];
extern pthread_mutex_t g_user_msgidlock[PNR_IMUSER_MAXNUM+1];
/***********************************************************************************
  Function:      sql_db_repair
  Description:  模块的数据库修复
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_db_repair(int uindex,int db_num,int db_tbl_index)
{
	int ret = 0;
    sqlite3 * p_dbhandler = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    char src_dbfile[PNR_FILENAME_MAXLEN+1] = {0};
    char bak_dbfile[PNR_FILENAME_MAXLEN+1] = {0};

    if((db_num < PNR_DBFILE_INDEX_GENERDB || db_num >= PNR_DBFILE_INDEX_BUTT)
        ||(db_tbl_index < PNR_DBTABLE_INDEX_GENERDB_GENERCONF || db_tbl_index >= PNR_DBTABLE_INDEX_BUTT))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_db_repair bad db_num(%d) tbl_inde(%d)",db_num,db_tbl_index);
        return ERROR;
    }
     
    //数据库备份
    switch(db_num)
    {
        case PNR_DBFILE_INDEX_GENERDB:
            strcpy(src_dbfile,DB_TOP_FILE);
            p_dbhandler = g_db_handle;
            break;
        case PNR_DBFILE_INDEX_FRIENDDB:
            strcpy(src_dbfile,DB_FRIENDLIST_FILE);
            p_dbhandler = g_friendsdb_handle;
            break;
        case PNR_DBFILE_INDEX_GROUPDB:
            strcpy(src_dbfile,DB_GROUPINFO_FILE);
            p_dbhandler = g_groupdb_handle;
            break;
        case PNR_DBFILE_INDEX_MSGLOGDB:
            if(uindex <=0 || uindex > PNR_IMUSER_MAXNUM)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_db_repair bad uindex (%d)",uindex );
                return ERROR;
            }
            snprintf(src_dbfile,PNR_FILENAME_MAXLEN,"%spnrouter_msglog.db", g_imusr_array.usrnode[uindex].userdata_pathurl);
            p_dbhandler = g_msglogdb_handle[uindex];
            break;
        case PNR_DBFILE_INDEX_MSGCACHEDB:
            if(uindex <=0 || uindex > PNR_IMUSER_MAXNUM)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_db_repair bad uindex (%d)",uindex );
                return ERROR;
            }
            snprintf(src_dbfile,PNR_FILENAME_MAXLEN,"%spnrouter_msgcache.db", g_imusr_array.usrnode[uindex].userdata_pathurl);
            p_dbhandler = g_msgcachedb_handle[uindex];
            break;
        default:
            return ERROR;
    }
    if(p_dbhandler)
    {
	    sqlite3_close(p_dbhandler);
    }
    strcpy(bak_dbfile,src_dbfile);
    strcat(bak_dbfile,"_bak");
    snprintf(sql_cmd,SQL_CMD_LEN,"cp -f %s %s",src_dbfile,bak_dbfile);
   
	return ret;
}

/**********************************************************************************
  Function:      dbupdate_intvalue_byname
  Description:   数据库更新整形参数
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int dbupdate_intvalue_byname(sqlite3 * pdb,char* table_name, char* key_name,int key_var)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(pdb == NULL || key_name == NULL || table_name == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"update %s set value=%d where name='%s' ;",table_name,key_var,key_name);
    if (sqlite3_exec(pdb, sql_cmd, 0, 0, &errMsg)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      dbupdate_strvalue_byname
  Description:   数据库更新string参数
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int dbupdate_strvalue_byname(sqlite3 * pdb,char* table_name, char* key_name,char* key_var)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(pdb == NULL || key_name == NULL || table_name == NULL || key_var == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"update %s set value='%s' where name='%s' ;",table_name,key_var,key_name);
    if (sqlite3_exec(pdb, sql_cmd, 0, 0, &errMsg)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      dbget_int_result
  Description:   数据库查询自定义int类别操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 dbget_int_result(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns <= 0)
    {
        return ERROR;
    }
    int* value = (int*)obj;
    if(column_values[0] == NULL)
    {
        *value = 0;
        return OK;
    }
    *value = atoi(column_values[0]);    
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"dbget_int_result:get int(%d)",*value);
    return OK;
}

/**********************************************************************************
  Function:      dbget_singstr_result
  Description:   数据库查询单个string类别操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 dbget_singstr_result(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns <= 0)
    {
        return ERROR;
    }
    struct db_string_ret* pret = (struct db_string_ret*)obj;
    if(pret == NULL)
    {
        return ERROR;
    }
	strncpy(pret->pbuf,column_values[0],pret->buf_len);
    return OK;
}
/***********************************************************************************
  Function:      sql_db_sync
  Description:  数据库同步,暂时空着
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_db_sync(int cur_db_version)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};

    if(cur_db_version == DB_VERSION_V1)
    {
        //初始化全局user_account_tbl表
        snprintf(sql_cmd,SQL_CMD_LEN,"create table user_account_tbl(id integer primary key autoincrement,lastactive,type,active,identifycode,mnemonic,usersn,"
            "userindex,nickname,loginkey,toxid,info,extinfo,pubkey,createtime);");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }     
        sql_tempaccount_sn_init();
        //初始化admin_count
        sql_adminaccount_init();

        //初始化全局tox_datafile_tbl表
        snprintf(sql_cmd,SQL_CMD_LEN,"create table tox_datafile_tbl(id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile);");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }  
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V2)
    {
    	snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','%s');",DB_DEVLOGINEKEY_KEYWORD,DB_DEFAULT_DEVLOGINKEY_VALUE);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V3)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','%s');",DB_DEVNAME_KEYWORD,DB_DEFAULT_DEVNAME_VALUE);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        //扩展user_account_tbl表,并初始化为空字符串
        snprintf(sql_cmd,SQL_CMD_LEN,"ALTER TABLE user_account_tbl ADD COLUMN pubkey varchar;");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"UPDATE user_account_tbl set pubkey='';");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        //增加初始化全局userdev_mapping_tbl表
        snprintf(sql_cmd,SQL_CMD_LEN,"create table userdev_mapping_tbl(id integer primary key autoincrement,userindex,usrid,devid,devname);");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }   
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V4)
    {
    	if(access(DB_GROUPINFO_FILE, F_OK)!=0)
    	{ 
    		sql_groupinfodb_init();
    	}
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V5)
    {
        //初始化全局userinfo_tbl表
        snprintf(sql_cmd,SQL_CMD_LEN,"create table userinfo_tbl(id integer primary key autoincrement,userindex,local,usrid,devid,avatar,md5,info);");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        } 
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V6)
    {
        //初始化全局userinfo_tbl表
        snprintf(sql_cmd,SQL_CMD_LEN,"ALTER TABLE groupmsg_tbl ADD COLUMN filekey char(512);");
        if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        } 
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V7)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',%d);",DB_PUBNETMODE_KEYWORD,PNRDEV_NETCONN_UNKNOWN);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',%d);",DB_FRPMODE_KEYWORD,PNRDEV_FRPCONNCT_OFF);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','');",DB_PUBNET_IPSTR_KEYWORD);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',0);",DB_PUBNET_PORT_KEYWORD);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',0);",DB_PUBNET_SSHPORT_KEYWORD);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',0);",DB_FRPPORT_KEYWORD);
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        cur_db_version++;
    }
    if(cur_db_version == DB_VERSION_V8)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"ALTER TABLE user_account_tbl ADD COLUMN createtime;");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        snprintf(sql_cmd,SQL_CMD_LEN,"UPDATE user_account_tbl SET createtime=lastactive;");
        if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        cur_db_version++;
    }
    //更新数据库版本
    snprintf(sql_cmd,SQL_CMD_LEN,"update generconf_tbl set value=%d where name='%s';",
        DB_CURRENT_VERSION,DB_VERSION_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	return OK;
}
/***********************************************************************************
  Function:      sql_db_check
  Description:  模块的数据库检测
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_db_check(void)
{
	int ret = 0;
	int cur_db_version = 0;
	int8 *errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

	if(access(DB_FRIENDLIST_FILE, F_OK)!=0)
	{ 
		ret += sql_friendsdb_init();
	}
    else if(sqlite3_open(DB_FRIENDLIST_FILE, &g_friendsdb_handle) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite3_open (%s)failed",DB_FRIENDLIST_FILE);
		unlink(DB_FRIENDLIST_FILE);
		return ERROR;
    }
	if(access(DB_GROUPINFO_FILE, F_OK)!=0)
	{ 
		ret += sql_groupinfodb_init();
	}
    else if(sqlite3_open(DB_GROUPINFO_FILE, &g_groupdb_handle) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite3_open (%s)failed",DB_GROUPINFO_FILE);
		unlink(DB_FRIENDLIST_FILE);
		return ERROR;
    }
	if(access(DB_TOP_FILE, F_OK)!=0)
	{ 
		ret += sql_db_init();
	}
	else if(sqlite3_open(DB_TOP_FILE, &g_db_handle) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite3_open failed");
		unlink(DB_TOP_FILE);
		return ERROR;
    }
	
	//获取当前数据库版本
	snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_VERSION_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&cur_db_version,&errMsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_db_check get cur_db_version failed");
		sqlite3_free(errMsg);
		unlink(DB_TOP_FILE);
        sqlite3_close(g_db_handle);
		return ERROR;
	}
    
	//如果版本不对，需要同步
	if(cur_db_version < DB_CURRENT_VERSION)
	{
		if(sql_db_sync(cur_db_version)!= OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_db_sync failed");
    		sqlite3_free(errMsg);
    		unlink(DB_TOP_FILE);
            sqlite3_close(g_db_handle);
    		return ERROR;
        }      
	}
	
	return ret;
}
/***********************************************************************************
  Function:      sql_adminaccount_init
  Description:  派生账号的数据库初始化
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_adminaccount_init(void)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};
    char account_sn[PNR_USN_MAXLEN+1] = {0};

    if(pnr_create_usersn(PNR_USER_TYPE_ADMIN,PNR_ADMINUSER_PSN_INDEX,account_sn) != OK)
    {
        return ERROR;
    }
    //user_account_tbl(id integer primary key autoincrement,lastactive,type,active,identifycode,mnemonic,usersn,userindex,nickname,loginkey,toxid,pubkey,info,extinfo,createtime);
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into user_account_tbl values(null,0,%d,%d,'%s','%s','%s',%d,'','','','','','',0);",
             PNR_USER_TYPE_ADMIN,FALSE,PNR_ADMINUSER_DEFAULT_IDCODE,"",account_sn,PNR_ADMINUSER_PSN_INDEX);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      sql_tempaccount_sn_init
  Description:  派生账号的数据库初始化
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_tempaccount_sn_init(void)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};
    char tmp_user_sn[PNR_USN_MAXLEN+1] = {0};

    if(pnr_create_usersn(PNR_USER_TYPE_TEMP,PNR_TEMPUSER_PSN_INDEX,tmp_user_sn) != OK)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','%s');",DB_TEMPACCOUNT_USN_KEYWORD,tmp_user_sn);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_tempaccount_sn_init(%s)",sql_cmd);
    return OK;
}
/***********************************************************************************
  Function:      sql_friendsdb_init
  Description:  模块的数据库初始化
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_friendsdb_init(void)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};

    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"sql_db_init start");
    if(sqlite3_open(DB_FRIENDLIST_FILE, &g_friendsdb_handle) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_friendsdb_init failed");
        return ERROR;
    }
	//初始化表
	snprintf(sql_cmd,SQL_CMD_LEN,"create table friends_tbl(id,timestamp,userid,friendid,friendname,userkey,oneway,remarks);");
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	return OK;
}
/***********************************************************************************
  Function:      sql_groupinfodb_init
  Description:  模块的数据库初始化
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_groupinfodb_init(void)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};

    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"sql_db_init start");
    if(sqlite3_open(DB_GROUPINFO_FILE, &g_groupdb_handle) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_groupinfodb_init failed");
        return ERROR;
    }
	//初始化表
	snprintf(sql_cmd,SQL_CMD_LEN,"create table grouplist_tbl(id,hash,owner,ownerid,verify,manager,gname,createtime);");
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"create table groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey);");
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"create table groupmsg_tbl(gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey);");
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"create table groupreadid_tbl(gid,userindex,lastmsgid,user);");
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"create table groupuserremark_tbl(gid,sid,fid,self,friend,remark);");
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"create table groupoperateinfo_tbl(gid,action,timestamp,fromId,toId,gname,fromuser,touser,ext);");
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	return OK;
}

/***********************************************************************************
  Function:      sql_msglogdb_init
  Description:  模块的数据库初始化
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_msglogdb_init(int index)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};
    int db_id = 0;
	char dbfile[128] = {0};

	snprintf(dbfile, sizeof(dbfile), "%spnrouter_msglog.db", g_imusr_array.usrnode[index].userdata_pathurl);

	if (access(dbfile, F_OK) != 0) {
#ifdef OPENWRT_ARCH
        if(sqlite3_open_v2(dbfile, &g_msglogdb_handle[index], SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_CREATE, NULL) != OK){
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "db open failed");
	        return ERROR;
	    }
	    //设置数据库的写同步，在系统断电的情况下可能丢失数据
	    sqlite3_exec(g_msglogdb_handle[index], "PRAGMA synchronous = OFF; ", 0,0,0);
        //开启WAL模式
        //sqlite3_exec(g_msgcachedb_handle[index], "PRAGMA journal_mode=WAL; ", 0,0,0);
#else
        if (sqlite3_open(dbfile, &g_msglogdb_handle[index]) != OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_msglogdb_init failed");
            return ERROR;
        }
#endif 
#if (DB_CURRENT_VERSION < DB_VERSION_V3)
		//初始化msglog表
		snprintf(sql_cmd,SQL_CMD_LEN,"create table msg_tbl("
		    "userindex,timestamp,id integer primary key autoincrement,"
		    "logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey);");
#else
        //初始化msglog表
        snprintf(sql_cmd,SQL_CMD_LEN,"create table msg_tbl("
            "userindex,timestamp,id integer primary key autoincrement,"
            "logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey);");
#endif
	    if (sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errMsg))
	    {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
	        sqlite3_free(errMsg);
	        return ERROR;
	    }
        //初始化filelist_tbl表
		snprintf(sql_cmd,SQL_CMD_LEN,"create table filelist_tbl("
		    "userindex,timestamp,id integer primary key autoincrement,version,"
		    "msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey);");
        if (sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
	} 
    else 
	{
#ifdef OPENWRT_ARCH
        if(sqlite3_open_v2(dbfile, &g_msglogdb_handle[index], SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_CREATE, NULL) != OK){
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "db open failed");
            return ERROR;
        }
        //设置数据库的写同步，在系统断电的情况下可能丢失数据
        sqlite3_exec(g_msglogdb_handle[index], "PRAGMA synchronous = OFF; ", 0,0,0);
        //开启WAL模式
        //sqlite3_exec(g_msgcachedb_handle[index], "PRAGMA journal_mode=WAL; ", 0,0,0);
#else
        if (sqlite3_open(dbfile, &g_msglogdb_handle[index]) != OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql_msglogdb_init failed");
            return ERROR;
        }
#endif 
    }
	
    //获取当前db的id最大值
    memset(sql_cmd,0,SQL_CMD_LEN);
    snprintf(sql_cmd,SQL_CMD_LEN,"SELECT max(id) sqlite_sequence from msg_tbl;");
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&g_imusr_array.usrnode[index].msglog_dbid,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    g_imusr_array.usrnode[index].msglog_dbid++;
    //获取当前db的id最大值,来判断是否有filelist表
    memset(sql_cmd,0,SQL_CMD_LEN);
    snprintf(sql_cmd,SQL_CMD_LEN,"SELECT max(id) sqlite_sequence from filelist_tbl;");
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&db_id,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errMsg);
        sqlite3_free(errMsg);
        memset(sql_cmd,0,SQL_CMD_LEN);
        snprintf(sql_cmd,SQL_CMD_LEN,"create table filelist_tbl("
		    "userindex,timestamp,id integer primary key autoincrement,version,"
		    "msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey);");
        if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errMsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }
        else
        {
            return OK;
        }
    }
    return OK;
}

/***********************************************************************************
  Function:      qlv_db_init
  Description:  模块的数据库初始化
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int sql_db_init(void)
{
    int8* errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};

    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"sql_db_init start");
    if(sqlite3_open(DB_TOP_FILE, &g_db_handle) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite3_open failed");
        return ERROR;
    }
	//初始化全局conf表
	snprintf(sql_cmd,SQL_CMD_LEN,"create table generconf_tbl(name,value);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',%d);",DB_VERSION_KEYWORD,DB_CURRENT_VERSION);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',%d);",DB_IMUSER_MAXNUM_KEYWORDK,PNR_IMUSER_MAXNUM);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','%s');",DB_DEVLOGINEKEY_KEYWORD,DB_DEFAULT_DEVLOGINKEY_VALUE);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','%s');",DB_DEVNAME_KEYWORD,DB_DEFAULT_DEVNAME_VALUE);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',%d);",DB_PUBNETMODE_KEYWORD,PNRDEV_NETCONN_UNKNOWN);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',%d);",DB_FRPMODE_KEYWORD,PNRDEV_FRPCONNCT_OFF);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s','');",DB_PUBNET_IPSTR_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',0);",DB_PUBNET_PORT_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',0);",DB_PUBNET_SSHPORT_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into generconf_tbl values('%s',0);",DB_FRPPORT_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    //初始化全局user_instance表
    snprintf(sql_cmd,SQL_CMD_LEN,"create table user_instance_tbl(userid primary key,"
    	"name,nickname,toxid,pathurl,datafile);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    //初始化log_cache_tbl
    snprintf(sql_cmd,SQL_CMD_LEN,"create table log_cache_tbl(timestamp,type,from_user,to_user,msg,ext);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    //初始化user_account_tbl
    snprintf(sql_cmd,SQL_CMD_LEN,"create table user_account_tbl(id integer primary key autoincrement,lastactive,type,active,identifycode,mnemonic,usersn,"
                "userindex,nickname,loginkey,toxid,info,extinfo,pubkey,createtime);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }    
    //初始化全局tox_datafile_tbl表
    snprintf(sql_cmd,SQL_CMD_LEN,"create table tox_datafile_tbl(id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }  
    //初始化全局userdev_mapping_tbl表
    snprintf(sql_cmd,SQL_CMD_LEN,"create table userdev_mapping_tbl(id integer primary key autoincrement,userindex,usrid,devid,devname);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    } 
    //初始化全局userinfo_tbl表
    snprintf(sql_cmd,SQL_CMD_LEN,"create table userinfo_tbl(id integer primary key autoincrement,userindex,local,usrid,devid,avatar,md5,info);");
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    } 
    //初始化临时账户的sn
    sql_tempaccount_sn_init();
    //初始化admin_count
    sql_adminaccount_init();
	return OK;
}

/*****************************************************************************
 函 数 名  : sql_msgcachedb_init
 功能描述  : 消息缓存db初始化
 输入参数  : 无
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月15日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int sql_msgcachedb_init(int index)
{
    int8 *errMsg = NULL;
    int8 sql_cmd[SQL_CMD_LEN] = {0};
	char dbfile[128] = {0};

	snprintf(dbfile, sizeof(dbfile), "%spnrouter_msgcache.db", g_imusr_array.usrnode[index].userdata_pathurl);

	if (access(dbfile, F_OK) != 0) {
#ifdef OPENWRT_ARCH
        if(sqlite3_open_v2(dbfile, &g_msgcachedb_handle[index], SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_CREATE, NULL) != OK){
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "db open failed");
	        return ERROR;
	    }
	    //设置数据库的写同步，在系统断电的情况下可能丢失数据
	    sqlite3_exec(g_msgcachedb_handle[index], "PRAGMA synchronous = OFF; ", 0,0,0);
#else        
        if (sqlite3_open(dbfile, &g_msgcachedb_handle[index]) != OK) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "db open failed");
            return ERROR;
        }
#endif
#if (DB_CURRENT_VERSION < DB_VERSION_V3)
		snprintf(sql_cmd, SQL_CMD_LEN, 
			"create table msg_tbl(id integer primary key autoincrement,"
			"fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey);");
#else
        snprintf(sql_cmd, SQL_CMD_LEN, 
            "create table msg_tbl(id integer primary key autoincrement,"
            "fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey);");
#endif
	    if (sqlite3_exec(g_msgcachedb_handle[index], sql_cmd, 0, 0, &errMsg)) {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)", sql_cmd, errMsg);
	        sqlite3_free(errMsg);
	        return ERROR;
	    }
	} else {
#ifdef OPENWRT_ARCH
        if(sqlite3_open_v2(dbfile, &g_msgcachedb_handle[index], SQLITE_OPEN_READWRITE | SQLITE_OPEN_NOMUTEX | SQLITE_OPEN_SHAREDCACHE | SQLITE_OPEN_CREATE, NULL) != OK){
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "db open failed");
            return ERROR;
        }
	    //设置数据库的写同步，在系统断电的情况下可能丢失数据
	    sqlite3_exec(g_msgcachedb_handle[index], "PRAGMA synchronous = OFF; ", 0,0,0);		
#else
        if (sqlite3_open(dbfile, &g_msgcachedb_handle[index]) != OK) {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "db open failed");
	        return ERROR;
	    }
#endif
    }
    //获取当前db的id最大值
    memset(sql_cmd,0,SQL_CMD_LEN);
    snprintf(sql_cmd,SQL_CMD_LEN,"SELECT max(id) sqlite_sequence from msg_tbl;");
    if(sqlite3_exec(g_msgcachedb_handle[index],sql_cmd,dbget_int_result,&g_imusr_array.usrnode[index].cachelog_dbid,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    g_imusr_array.usrnode[index].cachelog_dbid++;
	return OK;
}

/**********************************************************************************
  Function:      pnr_usr_instance_dbget
  Description:   数据库查询实例类别操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_usr_instance_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 3)
    {
        return ERROR;
    }
	struct im_user_struct *psinfo = (struct im_user_struct*)obj;
    if(psinfo == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_usr_instance_dbget obj is null");
        return ERROR;
    }
	if(column_values[0] != NULL)
	{
	    if(strcmp(column_values[0],psinfo->user_name) != OK)
        {
            strcpy(psinfo->user_name,column_values[0]);
        }   
    }
	if(column_values[1] != NULL)
	{
        strcpy(psinfo->user_nickname,column_values[1]);
    }
	if(column_values[2] != NULL)
	{
        strcpy(psinfo->user_toxid,column_values[2]);
    }
	return OK;
}

/***********************************************************************************
  Function:      pnr_usr_instance_get
  Description:  获取pnr user实例化信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_usr_instance_get(int index)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"select name,nickname,toxid from user_instance_tbl where userid=%d;",index);
	//DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_usr_instance_get sql_cmd2(%s)",sql_cmd);
	if(sqlite3_exec(g_db_handle,sql_cmd,pnr_usr_instance_dbget,&(g_imusr_array.usrnode[index]),&errMsg))
	{
		DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_usr_instance_get sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
		sqlite3_free(errMsg);
		return ERROR;
	}

    return OK;
}

/***********************************************************************************
  Function:      pnr_usr_instance_insert
  Description:  插入pnr user实例化信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_usr_instance_insert(int index)
{
	int8* errMsg = NULL;
    int count = 0;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    //这里要检查一下，避免重复插入
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from user_instance_tbl where toxid='%s';",
            g_imusr_array.usrnode[index].user_toxid);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_usr_instance_insert user instance exsit");
        return OK;
    }      
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into user_instance_tbl values(%d,'%s','%s','%s','%s','%s');",
             g_imusr_array.usrnode[index].user_index,g_imusr_array.usrnode[index].user_name,g_imusr_array.usrnode[index].user_nickname,
             g_imusr_array.usrnode[index].user_toxid,g_imusr_array.usrnode[index].userdata_pathurl,g_imusr_array.usrnode[index].userinfo_fullurl);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_usr_instance_insert:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_usr_instance_insert
  Description:  插入pnr user实例化信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_usr_instance_dbdelete_bytoxid(char* toxid)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(toxid == NULL)
    {
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"delete from user_instance_tbl where toxid='%s';",toxid);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_dbget_friendsall_byuserid
  Description:  获取某个用户的所有好友信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_dbget_friendsall_byuserid(int id,char* userid)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn;
    int index=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct im_userdev_mapping_struct tmp_devinfo;
    int i = 0;

    if(id <= 0 || id > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"select friendname,friendid,userkey,oneway,remarks from friends_tbl where userid='%s';",userid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_dbget_friendsall_byuserid sql_cmd(%s)",sql_cmd);
	if(sqlite3_get_table(g_friendsdb_handle, sql_cmd, &dbResult, &nRow, &nColumn, &errmsg) == SQLITE_OK)
    {
        index = nColumn; //字段值从index开始呀
        for( i = 0; i < nRow ; i++ )
        {
            snprintf(g_imusr_array.usrnode[id].friends[i].user_nickname,PNR_USERNAME_MAXLEN,"%s",dbResult[index]);
            snprintf(g_imusr_array.usrnode[id].friends[i].user_toxid,TOX_ID_STR_LEN+1,"%s",dbResult[index+1]);
            snprintf(g_imusr_array.usrnode[id].friends[i].user_pubkey,PNR_USER_PUBKEY_MAXLEN,"%s",dbResult[index+2]);
            g_imusr_array.usrnode[id].friends[i].oneway = atoi(dbResult[index+3]);
            snprintf(g_imusr_array.usrnode[id].friends[i].user_remarks,PNR_USERNAME_MAXLEN,"%s",dbResult[index+4]);
            g_imusr_array.usrnode[id].friends[i].exsit_flag =  TRUE;
            g_imusr_array.usrnode[id].friends[i].online_status = USER_ONLINE_STATUS_OFFLINE;
            pnr_uidhash_get(id,i+1,g_imusr_array.usrnode[id].friends[i].user_toxid,
                &g_imusr_array.usrnode[id].friends[i].hashid,g_imusr_array.usrnode[id].friends[i].u_hashstr);
            memset(&tmp_devinfo,0,sizeof(tmp_devinfo));
            strcpy(tmp_devinfo.user_toxid,g_imusr_array.usrnode[id].friends[i].user_toxid);
            if(pnr_usrdev_mappinginfo_sqlget(&tmp_devinfo) == OK)
            {
                if(tmp_devinfo.userindex == 0)
                {
                    g_imusr_array.usrnode[id].friends[i].local = FALSE;
                }
                else
                {
                    g_imusr_array.usrnode[id].friends[i].local = TRUE;
                }
                strcpy(g_imusr_array.usrnode[id].friends[i].user_devid,tmp_devinfo.user_devid);
                strcpy(g_imusr_array.usrnode[id].friends[i].user_devname,tmp_devinfo.user_devname);
            }
            index += nColumn;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"get node(%d) friend_name(%s) friend_id(%s) userkey(%s) remarks(%s) dev(%s:%s)",
                (i+1),g_imusr_array.usrnode[id].friends[i].user_nickname,g_imusr_array.usrnode[id].friends[i].user_toxid,
                g_imusr_array.usrnode[id].friends[i].user_pubkey,g_imusr_array.usrnode[id].friends[i].user_remarks,
                g_imusr_array.usrnode[id].friends[i].user_devid,g_imusr_array.usrnode[id].friends[i].user_devname);
        }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
        g_imusr_array.usrnode[id].friendnum = i;
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_friend_dbinsert
  Description:  插入一个pnr 好友关系
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_friend_dbinsert(char* from_toxid,char* to_toxid,char* nickname,char* userkey)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    int index = 0;
    int count = 0;
    
    if(from_toxid == NULL || to_toxid == NULL || nickname == NULL || userkey == NULL)
    {
        return ERROR;
    }

	for(index=1;index<=g_imusr_array.max_user_num;index++)
    {
        if(strcmp(from_toxid,g_imusr_array.usrnode[index].user_toxid) == OK)
        {
            break;
        }
    }
    if(index > g_imusr_array.max_user_num)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"not find user(%s)",from_toxid);
        return ERROR;
    }
	
    //这里要检查一下，避免重复插入
	snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from friends_tbl where userid='%s' and friendid='%s';",from_toxid,to_toxid);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,dbget_int_result,&count,&errMsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
		sqlite3_free(errMsg);
        return ERROR;
	}
	
    if(count > 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"update friends_tbl set friendname='%s',userkey='%s',oneway=0 where userid='%s' and friendid='%s';",
             nickname,userkey,from_toxid,to_toxid);
    }
	else
	{
		snprintf(sql_cmd,SQL_CMD_LEN,"insert into friends_tbl values(%d,%d,'%s','%s','%s','%s',0,'');",
             index,(int)time(NULL),from_toxid,to_toxid,nickname,userkey);
	}
    
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_friend_dbdelete
  Description:  删除一个pnr 好友关系
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_friend_dbdelete(char* from_toxid,char* to_toxid, int oneway)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    int index = 0;

    if(from_toxid == NULL || to_toxid == NULL)
    {
        return ERROR;
    }
    for(index=1;index<=g_imusr_array.max_user_num;index++)
    {
        if(strcmp(from_toxid,g_imusr_array.usrnode[index].user_toxid) == OK)
        {
            break;
        }
    }
    if(index > g_imusr_array.max_user_num)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"not find user(%s)",from_toxid);
        return ERROR;
    }

	if (oneway) {
		snprintf(sql_cmd,SQL_CMD_LEN,"update friends_tbl set oneway=%d where userid='%s' and friendid='%s';",oneway, from_toxid,to_toxid);
	} else {
		snprintf(sql_cmd,SQL_CMD_LEN,"delete from friends_tbl where userid='%s' and friendid='%s';",from_toxid,to_toxid);
	}
	
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }

	if (!oneway) {
		if(pnr_filelog_delete_byfiletype(PNR_IM_MSGTYPE_ALL,from_toxid,to_toxid) != OK)
	    {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_friend_dbdelete:pnr_filelog_delete_byfiletype error");
	    }
	}
	
    return OK;
}
/***********************************************************************************
  Function:      pnr_friend_dbupdate_nicename_bytoxid
  Description:  更新好友昵称
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_friend_dbupdate_nicename_bytoxid(char* from_toxid,char* to_toxid,char* nickname)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(from_toxid == NULL || to_toxid == NULL || nickname == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"update friends_tbl set friendname='%s' where userid='%s' and friendid='%s';",nickname,from_toxid,to_toxid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_friend_dbupdate_remarks_bytoxid
  Description:  更新好友备注
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_friend_dbupdate_remarks_bytoxid(char* from_toxid,char* to_toxid,char* remarks)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(from_toxid == NULL || to_toxid == NULL || remarks == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"update friends_tbl set remarks='%s' where userid='%s' and friendid='%s';",remarks,from_toxid,to_toxid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_friend_get_remark
 功能描述  : 获取好友备注或者昵称
 输入参数  : char *userid    
             char *friendid  
             char *value     
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月14日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_friend_get_remark(char *userid, char *friendid, char *value, int len)
{
	char sql[1024] = {0};
	char **dbResult; 
    char *errmsg;
    int nRow, nColumn;
    int offset = 0;

	snprintf(sql, sizeof(sql), "select friendname,remarks from friends_tbl where userid='%s' and "
		"friendid='%s';", userid, friendid);

	if (sqlite3_get_table(g_friendsdb_handle, sql, &dbResult, &nRow, &nColumn, &errmsg) == SQLITE_OK) {
        offset = nColumn;

		if (strlen(dbResult[offset+1]))
			strncpy(value, dbResult[offset+1], len);
		else
			strncpy(value, dbResult[offset], len);
		
		sqlite3_free_table(dbResult);
    } else {
    	DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql(%s) err(%s)", sql, errmsg);
		sqlite3_free(errmsg);
	}

	return 0;
}
/*****************************************************************************
 函 数 名  : pnr_friend_get_pubkey_bytoxid
 功能描述  : 获取好友备注或者昵称
 输入参数  : char *userid    
             char *friendid  
             char *pubkey     
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月14日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_friend_get_pubkey_bytoxid(char *userid, char *friendid, char *pubkey)
{
	char sql[1024] = {0};
    char *errmsg;
    struct db_string_ret db_ret;
    db_ret.buf_len = PNR_LOGINKEY_MAXLEN;
    db_ret.pbuf = pubkey;
	snprintf(sql, sizeof(sql), "select userkey from friends_tbl where userid='%s' and friendid='%s';", userid, friendid);
    if(sqlite3_exec(g_friendsdb_handle,sql,dbget_singstr_result,&db_ret,&errmsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_friend_get_pubkey_bytoxid failed");
		sqlite3_free(errmsg);
		return ERROR;
	}
	return OK;
}
/*****************************************************************************
 函 数 名  : pnr_friend_del_bytoxid
 功能描述  pnr_friend_delete_bytoxid
 输入参数  : char *userid      
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2019年1月14日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_friend_delete_bytoxid(char *userid)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(userid == NULL)
    {
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"delete from friends_tbl where userid='%s';",userid);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_msglog_getid
 功能描述  : 添加一条msglod，并获取表ID
 输入参数  : int *msgid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月24日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msglog_getid(int index, int *logid)
{
#if 0
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};

    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msglog_getid: try to get logid");
    sqlite3_exec(g_msglogdb_handle[index],"begin;",0,0,0); 
    //msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey
	snprintf(sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
        "values(0,0,null,0,0,0,'','','','',0,'','');");
    if (sqlite3_exec(g_msglogdb_handle[index], sql, 0, 0, &err)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql, err);
        sqlite3_free(err);
        return ERROR;
    }
    sqlite3_exec(g_msglogdb_handle[index],"commit;",0,0,0); 
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msglog_getid: insert ok");
	*logid = sqlite3_last_insert_rowid(g_msglogdb_handle[index]);
#else
    pthread_mutex_lock(&(g_user_msgidlock[index]));
    *logid = (int)g_imusr_array.usrnode[index].msglog_dbid;
    g_imusr_array.usrnode[index].msglog_dbid++;
    pthread_mutex_unlock(&(g_user_msgidlock[index]));
#endif
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) pnr_msglog_getid(%d)",index,*logid);
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_msglog_delid
 功能描述  : 删除指定logid的消息日志
 输入参数  : int logid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月24日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msglog_delid(int index, int id)
{
    int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};

    //msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey,sign,nonce,prikey
	snprintf(sql, MSGSQL_CMD_LEN, "delete from msg_tbl where id=%d);", id);
		
    if (sqlite3_exec(g_msglogdb_handle[index], sql, 0, 0, &err)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql, err);
        sqlite3_free(err);
        return ERROR;
    }
    
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbinsert
  Description:  插入一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:   db_id
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbinsert(int recode_userindex,int msgtype,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext, int ext2)
{
	int8* errMsg = NULL;
    char *ext = "";
    char *p_newskey = "";
    char *p_newdkey = "";
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    if (from_toxid == NULL || to_toxid == NULL || pmsg == NULL)
    {
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbinsert:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    }
    if (pext) 
    {
        ext = pext;
    }
    if(skey != NULL)
    {
        p_newskey = skey;
    }
    if(dkey != NULL)
    {
        p_newdkey = dkey;
    }

	if (log_id) {
		snprintf(sql_cmd, MSGSQL_CMD_LEN, "select id from msg_tbl where from_user='%s' and logid=%d;",
			from_toxid, log_id);

		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		int ret = sqlite3_get_table(g_msglogdb_handle[recode_userindex], sql_cmd, &dbResult, &nRow, &nColumn, &errMsg);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", from_toxid, to_toxid);
				sqlite3_free_table(dbResult);
				return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql err(%s)", sql_cmd);
			sqlite3_free(errMsg);
		}
	}
	
    pthread_mutex_lock(&(g_user_msgidlock[recode_userindex]));

#if (DB_CURRENT_VERSION < DB_VERSION_V3)
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey);
    snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
        "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey) "
        "values(%d,%d,null,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s');",
        recode_userindex,(int)time(NULL),log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
#else
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,null,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','','%s');",
            recode_userindex,(int)time(NULL),log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);    
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,null,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','','%s');",
            recode_userindex,(int)time(NULL),log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
    }

#endif
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbinsert:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[recode_userindex], p_sql, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
        return ERROR;
    }
    g_imusr_array.usrnode[recode_userindex].msglog_dbid++;
    pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }
    return OK;
}

/***********************************************************************************
  Function:      pnr_msglog_dbinsert_specifyid
  Description:  插入一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:   db_id
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbinsert_specifyid(int recode_userindex,int msgtype,int db_id,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext, int ext2)
{
	int8* errMsg = NULL;
    char *ext = "";
    char *p_newskey = "";
    char *p_newdkey = "";
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    
    if (from_toxid == NULL || to_toxid == NULL || pmsg == NULL) 
    {
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbinsert_specifyid:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    }
    if (pext) 
    {
        ext = pext;
    }
    if(skey != NULL)
    {
        p_newskey = skey;
    }
    if(dkey != NULL)
    {
        p_newdkey = dkey;
    }

	if (log_id) {
		snprintf(sql_cmd, MSGSQL_CMD_LEN, "select id from msg_tbl where from_user='%s' and logid=%d;",
			from_toxid, log_id);

		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		int ret = sqlite3_get_table(g_msglogdb_handle[recode_userindex], sql_cmd, &dbResult, &nRow, &nColumn, &errMsg);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", from_toxid, log_id);
				sqlite3_free_table(dbResult);
				return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql err(%s)", sql_cmd);
			sqlite3_free(errMsg);
		}
	}
	
    pthread_mutex_lock(&(g_user_msgidlock[recode_userindex]));
#if (DB_CURRENT_VERSION < DB_VERSION_V3)
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey);
    snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
        "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey) "
        "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s');",
        recode_userindex,(int)time(NULL),db_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
#else
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','','%s');",
            recode_userindex,(int)time(NULL),db_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','','%s');",
            recode_userindex,(int)time(NULL),db_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);  
    }
#endif
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbinsert:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[recode_userindex], p_sql, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
        return ERROR;
    }
    pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }
    return OK;
}

/***********************************************************************************
  Function:      pnr_msglog_dbupdate
  Description:  更新一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbupdate(int recode_userindex,int msgtype,int log_id,int msgstatus,
    char* from_toxid,char* to_toxid,char* pmsg,char* skey,char* dkey,char* pext, int ext2)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char *ext = "";
    char *p_newskey = "";
    char *p_newdkey = "";
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    if (from_toxid == NULL || to_toxid == NULL || pmsg == NULL) 
    {
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbupdate:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    }
    if (pext) 
    {
        ext = pext;
    }
    if(skey != NULL)
    {
        p_newskey = skey;
    }
    if(dkey != NULL)
    {
        p_newdkey = dkey;
    }
//修改为直接插入    
#if 0
    //msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey,sign,nonce,prikey
    snprintf(sql_cmd, MSGSQL_CMD_LEN, "update msg_tbl set userindex=%d,"
        "timestamp=%d,msgtype=%d,status=%d,from_user='%s',to_user='%s',"
        "msg='%s',ext='%s',ext2=%d,skey='%s',dkey='%s',logid=%d where id=%d;",
        recode_userindex,(int)time(NULL),msgtype,msgstatus,
        from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey,log_id,log_id);
#else
#if (DB_CURRENT_VERSION < DB_VERSION_V3)
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey);
    snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
        "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey) "
        "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s');",
        recode_userindex,(int)time(NULL),log_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
#else
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','','%s');",
            recode_userindex,(int)time(NULL),log_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','','%s');",
            recode_userindex,(int)time(NULL),log_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_newskey,p_newdkey);
    }
#endif
#endif    
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbupdate:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[recode_userindex], p_sql, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbinsert_v3
  Description:  插入一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:   db_id
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbinsert_v3(int recode_userindex,int msgtype,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* sign,char* nonce,char* prikey,char* pext, int ext2)
{
	int8* errMsg = NULL;
    char *ext = "";
    char *p_sign = "";
    char *p_nonce = "";
    char *p_prikey = "";
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    
    if (from_toxid == NULL || to_toxid == NULL || pmsg == NULL)
    {
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbinsert_v3:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    }
    if (pext)
    {
        ext = pext;
    }
    if(sign != NULL)
    {
        p_sign = sign;
    }
    if(nonce != NULL)
    {
        p_nonce = nonce;
    }
    if(prikey != NULL)
    {
        p_prikey = prikey;
    }

	if (log_id) {
		snprintf(sql_cmd, MSGSQL_CMD_LEN, "select id from msg_tbl where from_user='%s' and logid=%d;",
			from_toxid, log_id);

		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		int ret = sqlite3_get_table(g_msglogdb_handle[recode_userindex], sql_cmd, &dbResult, &nRow, &nColumn, &errMsg);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", from_toxid, to_toxid);
				sqlite3_free_table(dbResult);
				return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql err(%s)", sql_cmd);
			sqlite3_free(errMsg);
		}
	}
	
    pthread_mutex_lock(&(g_user_msgidlock[recode_userindex]));
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,null,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
            recode_userindex,(int)time(NULL),log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_sign,p_nonce,p_prikey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,null,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
            recode_userindex,(int)time(NULL),log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_sign,p_nonce,p_prikey);
    }
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbinsert:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[recode_userindex], p_sql, 0, 0, &errMsg)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
        if(sql_malloc_flag == TRUE)
        {
            free(p_sql);
        }
        return ERROR;
    }
    g_imusr_array.usrnode[recode_userindex].msglog_dbid++;
    pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbinsert_specifyid
  Description:  插入一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:   db_id
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbinsert_specifyid_v3(int recode_userindex,int msgtype,int db_id,int log_id,int msgstatus, 
    char* from_toxid,char* to_toxid,char* pmsg,char* sign,char* nonce,char* prikey,char* pext, int ext2)
{
	int8* errMsg = NULL;
    char *ext = "";
    char *p_sign = "";
    char *p_nonce = "";
    char *p_prikey = "";
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    
    if (from_toxid == NULL || to_toxid == NULL || pmsg == NULL) {
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbinsert_specifyid_v3:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    } 
    if (pext) 
    {
        ext = pext;
    }
    if(sign != NULL)
    {
        p_sign = sign;
    }
    if(nonce != NULL)
    {
        p_nonce = nonce;
    }
    if(prikey != NULL)
    {
        p_nonce = nonce;
    }

	if (log_id) {
		snprintf(sql_cmd, MSGSQL_CMD_LEN, "select id from msg_tbl where from_user='%s' and logid=%d;",
			from_toxid, log_id);

		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		int ret = sqlite3_get_table(g_msglogdb_handle[recode_userindex], sql_cmd, &dbResult, &nRow, &nColumn, &errMsg);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", from_toxid, log_id);
				sqlite3_free_table(dbResult);
				return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql err(%s)", sql_cmd);
			sqlite3_free(errMsg);
		}
	}
	
    pthread_mutex_lock(&(g_user_msgidlock[recode_userindex]));
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
            recode_userindex,(int)time(NULL),db_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_sign,p_nonce,p_prikey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
            recode_userindex,(int)time(NULL),db_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_sign,p_nonce,p_prikey);
    }
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbinsert:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[recode_userindex], p_sql, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
        if(sql_malloc_flag == TRUE)
        {
            free(p_sql);
        }
        return ERROR;
    }
    pthread_mutex_unlock(&(g_user_msgidlock[recode_userindex]));
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbupdate_v3
  Description:  更新一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbupdate_v3(int recode_userindex,int msgtype,int log_id,int msgstatus,
    char* from_toxid,char* to_toxid,char* pmsg,char* sign,char* nonce,char* prikey,char* pext, int ext2)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char *ext = "";
    char *p_sign = "";
    char *p_nonce = "";
    char *p_prikey = "";
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;

    if (from_toxid == NULL || to_toxid == NULL || pmsg == NULL) 
    {
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbinsert_specifyid_v3:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    } 
    if (pext) 
    {
        ext = pext;
    }
    if(p_sign != NULL)
    {
        p_sign = sign;
    }
    if(p_nonce != NULL)
    {
        p_nonce = nonce;
    }
    if(prikey != NULL)
    {
        p_prikey = prikey;
    }
    //table msg_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
            recode_userindex,(int)time(NULL),log_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_sign,p_nonce,p_prikey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,ext,ext2,sign,nonce,prikey) "
            "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
            recode_userindex,(int)time(NULL),log_id,log_id,msgtype,msgstatus,from_toxid,to_toxid,pmsg,ext,ext2,p_sign,p_nonce,p_prikey);
    }
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbupdate:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[recode_userindex], p_sql, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        if(sql_malloc_flag == TRUE)
        {
            free(p_sql);
        }  
        return ERROR;
    }
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }  
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbupdate_stauts_byid
  Description:  更新一条记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbupdate_stauts_byid(int index,int db_id,int msgstatus)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    int cur_status = 0;    

    if(msgstatus < MSG_STATUS_UNKNOWN || msgstatus > MSG_STATUS_READ_OK)
    {
        return ERROR;
    }
    //这里要检查一下
    snprintf(sql_cmd,SQL_CMD_LEN,"select status from msg_tbl where userindex=%d and id=%d;",index,db_id);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&cur_status,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql(%s) get cur_status failed",sql_cmd);
        sqlite3_free(errMsg);
        return ERROR;
    }

    if(cur_status  == msgstatus)
    {
        return OK;
    }
    /*"userindex,timestamp,id integer primary key autoincrement,
            logid,msgtype,status,from_user,to_user,msg,ext,ext2,skey,dkey*/
    snprintf(sql_cmd, MSGSQL_CMD_LEN, "update msg_tbl set status=%d where userindex=%d and id=%d;",msgstatus,index,db_id);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbupdate_stauts_byid:sql_cmd(%s)",sql_cmd);
    if (sqlite3_exec(g_msglogdb_handle[index], sql_cmd, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbget_logid_byid
  Description:  根据id获取logid
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbget_logid_byid(int index,int id,int* logid)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    int target_id = 0;    

    //这里要检查一下
    snprintf(sql_cmd,SQL_CMD_LEN,"select logid from msg_tbl where id=%d;",id);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&target_id,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql(%s) get cur_status failed",sql_cmd);
        sqlite3_free(errMsg);
        return ERROR;
    }
    *logid = target_id;
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbget_dbid_bylogid
  Description:  根据好友名称和logid获取该条记录的id
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbget_dbid_bylogid(int index,int log_id,char* from,char* to,int* db_id)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    int target_id = 0;    
    if(from == NULL || to == NULL)
    {
        return ERROR;
    }
    //这里要检查一下
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from msg_tbl where logid=%d and from_user='%s' and to_user='%s';",
    log_id,from,to);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&target_id,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql(%s) get cur_status failed",sql_cmd);
        sqlite3_free(errMsg);
        return ERROR;
    }
    *db_id = target_id;
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msglog_dbget_dbid_bylogid:sql(%s),db_id(%d)",sql_cmd,*db_id);
    return OK;
}
/**********************************************************************************
  Function:      pnr_msglog_dbget_callbak
  Description:   数据库查询消息记录回掉
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_msglog_dbget_callbak(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 13)
    {
        return ERROR;
    }
	struct im_sendmsg_msgstruct *pmsg = (struct im_sendmsg_msgstruct*)obj;
    if(pmsg == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msglog_dbget_callbak obj is null");
        return ERROR;
    }
	if(column_values[0] != NULL)
	{
        pmsg->db_id = atoi(column_values[0]);
    }
	if(column_values[1] != NULL)
	{
        pmsg->log_id = atoi(column_values[1]);
    }
	if(column_values[2] != NULL)
	{
        pmsg->timestamp = atoi(column_values[2]);
    }
	if(column_values[3] != NULL)
	{
        pmsg->msg_status = atoi(column_values[3]);
    }
	if(column_values[4] != NULL)
	{
        snprintf(pmsg->fromuser_toxid,TOX_ID_STR_LEN+1,"%s",column_values[4]);
    }
	if(column_values[5] != NULL)
	{
        snprintf(pmsg->touser_toxid,TOX_ID_STR_LEN+1,"%s",column_values[5]);
    }
	if(column_values[6] != NULL)
	{
        snprintf(pmsg->msg_buff,IM_MSG_PAYLOAD_MAXLEN+1,"%s",column_values[6]);
    }
	if(column_values[7] != NULL)
	{
        pmsg->msgtype = atoi(column_values[7]);
    }
	if(column_values[8] != NULL)
	{
        snprintf(pmsg->ext,IM_MSG_MAXLEN+1,"%s",column_values[8]);
    }
	if(column_values[9] != NULL)
	{
        pmsg->ext2 = atoi(column_values[9]);
    }
	if(column_values[10] != NULL)
	{
        snprintf(pmsg->sign,PNR_RSA_KEY_MAXLEN+1,"%s",column_values[10]);
    }
	if(column_values[11] != NULL)
	{
        snprintf(pmsg->nonce,TOX_ID_STR_LEN+1,"%s",column_values[11]);
    }
	if(column_values[12] != NULL)
	{
        snprintf(pmsg->prikey,IM_MSG_MAXLEN+1,"%s",column_values[12]);
    }
	return OK;
}

/***********************************************************************************
  Function:      pnr_msglog_dbget_byid
  Description:  根据id获取该条记录的信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbget_byid(int index,int db_id,struct im_sendmsg_msgstruct* pmsg)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    if(pmsg == NULL || index < 0 || index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    //这里要检查一下
    snprintf(sql_cmd,SQL_CMD_LEN,"select id,logid,timestamp,status,"
				"from_user,to_user,msg,msgtype,ext,ext2,sign,nonce,"
				"prikey,id from msg_tbl where id=%d",db_id);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,pnr_msglog_dbget_callbak,pmsg,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql(%s) get cur_status failed",sql_cmd);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbupdate_filename_byid
  Description:  更新一条记录的文件名称
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbupdate_filename_byid(int uindex,int dbid,char* filename, char* filepath)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};

    if (filename == NULL || filepath == NULL) {
        return ERROR;
    }
    snprintf(sql_cmd, MSGSQL_CMD_LEN, "update msg_tbl set msg='%s',ext='%s' where id=%d;",filename,filepath,dbid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbupdate:sql_cmd(%s)",sql_cmd);
    if (sqlite3_exec(g_msglogdb_handle[uindex], sql_cmd, 0, 0, &errMsg)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_msglog_dbdelete
  Description:  删除消息记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_msglog_dbdelete(int recode_userindex,int msgtype,int log_id, 
    char* from_toxid,char* to_toxid)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
	char **dbResult; 
    int nRow = 0, nColumn = 0;
    int offset = 0, i = 0;
	int filetype = 0;
	char filepath[UPLOAD_FILENAME_MAXLEN * 2] = {0};

    if(from_toxid == NULL || to_toxid == NULL)
    {
        return ERROR;
    }

	//delete file
	snprintf(sql_cmd, SQL_CMD_LEN, "select msgtype,ext from msg_tbl where "
		"logid=%d and from_user='%s' and to_user='%s';",
		log_id, from_toxid, to_toxid);
    if (sqlite3_get_table(g_msglogdb_handle[recode_userindex], sql_cmd, &dbResult, &nRow, 
            &nColumn, &errMsg) == SQLITE_OK)
    {
        offset = nColumn;
		
        for (i = 0; i < nRow; i++)
        {
        	filetype = atoi(dbResult[offset]);

			switch (filetype) {
			case PNR_IM_MSGTYPE_FILE:
			case PNR_IM_MSGTYPE_IMAGE:
			case PNR_IM_MSGTYPE_AUDIO:
			case PNR_IM_MSGTYPE_MEDIA:
				snprintf(filepath, UPLOAD_FILENAME_MAXLEN * 2, "%s%s",
					WS_SERVER_INDEX_FILEPATH, dbResult[offset + 1]);
				unlink(filepath);
				break;
			}

			offset += nColumn;
        }

		sqlite3_free_table(dbResult);
	}
			
    if(log_id != 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"delete from msg_tbl where "
            "logid=%d and from_user='%s' and to_user='%s';",
            log_id, from_toxid, to_toxid);
    }
    else//为0就删除两人见全部数据
    {
        //删除某一类型消息全部记录
        if(msgtype >= PNR_IM_MSGTYPE_TEXT && msgtype <= PNR_IM_MSGTYPE_AVATAR)
        {
            snprintf(sql_cmd,SQL_CMD_LEN,"delete from msg_tbl where "
                "((from_user='%s' and to_user='%s') or "
                "(from_user='%s' and to_user='%s')) and msgtype=%d;",from_toxid,to_toxid,to_toxid,from_toxid,msgtype);
        
        }
        //删除两人之间所有类型消息记录
        else
        {
            snprintf(sql_cmd,SQL_CMD_LEN,"delete from msg_tbl where "
                "((from_user='%s' and to_user='%s') or "
                "(from_user='%s' and to_user='%s'));",from_toxid,to_toxid,to_toxid,from_toxid);
        }
    }
    
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msglog_dbdelete:sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_msglogdb_handle[recode_userindex],sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_msgcache_getid
 功能描述  : 获取消息id
 输入参数  : int *msgid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月16日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_getid(int index, int *msgid)
{
#if 0
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};

    //id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype
	snprintf(sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
        "values(null,'','',0,0,'',%d,'','',0,0,0,'','');", (int)time(NULL));
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msgcache_getid: try to get logid(%s)",sql);
    sqlite3_exec(g_msglogdb_handle[index],"begin;",0,0,0); 
    if (sqlite3_exec(g_msgcachedb_handle[index], sql, 0, 0, &err)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s) index(%d)", sql, err, index);
        sqlite3_free(err);
        return ERROR;
    }
    sqlite3_exec(g_msglogdb_handle[index],"commit;",0,0,0); 
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msgcache_getid: insert ok");
	*msgid = sqlite3_last_insert_rowid(g_msgcachedb_handle[index]);
#else
    pthread_mutex_lock(&(g_user_msgidlock[index]));
    *msgid = (int)g_imusr_array.usrnode[index].cachelog_dbid;
    g_imusr_array.usrnode[index].cachelog_dbid++;
    pthread_mutex_unlock(&(g_user_msgidlock[index]));
#endif
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) pnr_msgcache_getid(%d)",index,*msgid);
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_msgcache_dbinsert
 功能描述  : 插入消息到缓存db
 输入参数  : int index     
             int msgtype   
             int *msgid    
             char *fromid  
             char *toid    
             char *pmsg    
             char *pext    
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月15日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_dbinsert(int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, char *filename, char *filepath, int logid, int ctype, int ftype,char* skey,char* dkey)
{
    int ret = 0;
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};
    int userid = 0;
    int filesize = 0;
    struct stat fstat;
    struct lws_cache_msg_struct *msg = NULL;
	struct lws_cache_msg_struct *tmsg = NULL;
    struct lws_cache_msg_struct *n = NULL;
    char fpath[PNR_FILEPATH_MAXLEN+1] = {0};
    char *fname = "";
    char *p_newskey = "";
    char *p_newdkey = "";
    int msg_totallen = 0;
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;

    if(len <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:len(%d) err",len);
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql;
    }

    //id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey
    if (filepath) {
        ret = stat(filepath, &fstat);
        if (ret < 0) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get file stat err(%s-%d)", filepath, errno);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
        } else {
            filesize = fstat.st_size;
            DEBUG_PRINT(DEBUG_LEVEL_INFO, "get file size(%s-%d)", filepath, filesize);
        }
    }

	if (filename) {
        fname = filename;
    }

    if (ctype == PNR_MSG_CACHE_TYPE_TOX || ctype == PNR_MSG_CACHE_TYPE_TOXF) {
        userid = get_indexbytoxid(fromid);
        if (!userid) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get user(%s) index err", fromid);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
        }

		snprintf(fpath, sizeof(fpath), "/user%d/s/%s", userid, fname);
    } else {
        userid = get_indexbytoxid(toid);
        if (!userid) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get user(%s) index err", toid);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
        }

		snprintf(fpath, sizeof(fpath), "/user%d/r/%s", userid, fname);
    }
    if(filepath)
    {
        memset(fpath,0,PNR_FILEPATH_MAXLEN);
        if(strncmp(filepath,WS_SERVER_INDEX_FILEPATH,strlen(WS_SERVER_INDEX_FILEPATH)) == OK)
        {
            strcpy(fpath,filepath+strlen(WS_SERVER_INDEX_FILEPATH));
        }
        else
        {
            strcpy(fpath,filepath);
        }
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msgcache_dbinsert: src(%s) fpath(%s)",filepath,fpath);
    }

    if (skey) {
        p_newskey = skey;
    }
    if (dkey) {
        p_newdkey = dkey;
    }
	if (logid) {
		snprintf(p_sql, MSGSQL_CMD_LEN, "select id from msg_tbl where fromid='%s' and logid=%d;",
			fromid, logid);

		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		ret = sqlite3_get_table(g_msgcachedb_handle[userid], p_sql, &dbResult, &nRow, &nColumn, &err);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", fromid, logid);
				sqlite3_free_table(dbResult);
                if(sql_malloc_flag == TRUE)
                {
                    free(p_sql);
                }  
                return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql err(%s)", p_sql);
			sqlite3_free(err);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
		}
	}
    
#if 0//换成直接插入方式    
    snprintf(sql, MSGSQL_CMD_LEN, "update msg_tbl set fromid='%s',"
		"toid='%s',type=%d,ctype=%d,msg='%s',len=%d,filename='%s',filepath='%s',"
		"filesize=%d,logid=%d,ftype=%d,skey='%s',dkey='%s' where id=%d;", 
		fromid, toid, type, ctype, pmsg, len, fname, fpath, filesize, 
		logid, ftype, p_newskey, p_newdkey, msgid);
#else
#if (DB_CURRENT_VERSION < DB_VERSION_V3)
    //table msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey);
    snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
    "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,skey,dkey)"
    "values (%d,'%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,%d,'%s','%s');",
        msgid,fromid,toid,type,ctype,pmsg,len,fname,fpath,
        filesize,logid, ftype, p_newskey, p_newdkey);
#else
    //table msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey)"
            "values (%d,'%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,%d,'%s','','%s');",
            msgid,fromid,toid,type,ctype,pmsg,len,fname,fpath,
            filesize,logid, ftype, p_newskey, p_newdkey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey)"
            "values (%d,'%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,%d,'%s','','%s');",
            msgid,fromid,toid,type,ctype,pmsg,len,fname,fpath,
            filesize,logid, ftype, p_newskey, p_newdkey);
    }
#endif
#endif
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)", p_sql);
    if (sqlite3_exec(g_msgcachedb_handle[userid], p_sql, 0, 0, &err))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", p_sql, err);
        sqlite3_free(err);
        if(sql_malloc_flag == TRUE)
        {
            free(p_sql);
        }
        return ERROR;
    }
    msg_totallen = sizeof(struct lws_cache_msg_struct) + len + 1;
	msg = (struct lws_cache_msg_struct *)malloc(msg_totallen);
	if (!msg) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "malloc err!");
        if(sql_malloc_flag == TRUE)
        {
            free(p_sql);
        }
		return ERROR;
	}
    memset(msg, 0, msg_totallen);
    INIT_LIST_HEAD(&msg->list);
	msg->userid = userid;
	msg->msgid = msgid;
	msg->msglen = len;
	msg->timestamp = time(NULL);
    msg->type = type;
    msg->ctype = ctype;
    msg->ftype = ftype;
    msg->notice_flag = FALSE;
    msg->filesize = filesize;
    msg->logid = logid;
	strncpy(msg->msg, pmsg, len);
	strncpy(msg->fromid, fromid, TOX_ID_STR_LEN);
    strncpy(msg->toid, toid, TOX_ID_STR_LEN);
    strncpy(msg->filename, fname, UPLOAD_FILENAME_MAXLEN - 1);
    strncpy(msg->filepath, fpath, UPLOAD_FILENAME_MAXLEN*2 - 1);
    strncpy(msg->srckey, p_newskey, PNR_RSA_KEY_MAXLEN);
    strncpy(msg->dstkey, p_newdkey, PNR_RSA_KEY_MAXLEN);
	pthread_mutex_lock(&lws_cache_msglock[userid]);
    if (!list_empty(&g_lws_cache_msglist[userid].list)) {
		list_for_each_safe(tmsg, n, &g_lws_cache_msglist[userid].list, struct lws_cache_msg_struct, list) {
			if (tmsg->logid && tmsg->logid == logid) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO,"msg cache repeat, no add");
                free(msg);
                goto OUT;
			}
		}
		
		list_for_each_safe(tmsg, n, &g_lws_cache_msglist[userid].list, struct lws_cache_msg_struct, list) {
			if (tmsg->msgid > msgid) {
				list_add_before(&msg->list, &tmsg->list);
				goto OUT;
			}
		}
	}
	list_add_tail(&msg->list, &g_lws_cache_msglist[userid].list);

OUT:
    pthread_mutex_unlock(&lws_cache_msglock[userid]);
    DEBUG_PRINT(DEBUG_LEVEL_INFO, "inset cache msg(%d:%s) len(%d)", userid, pmsg,len);    
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_msgcache_dbinsert_v3
 功能描述  : 插入消息到缓存db
 输入参数  : int index     
             int msgtype   
             int *msgid    
             char *fromid  
             char *toid    
             char *pmsg    
             char *pext    
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月15日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_dbinsert_v3(int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, char *filename, char *filepath, int logid, int ctype, 
    int ftype,char* sign,char* nonce,char* prikey)
{
    int ret = 0;
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};
    int userid = 0;
    int filesize = 0;
    struct stat fstat;
    struct lws_cache_msg_struct *msg = NULL;
	struct lws_cache_msg_struct *tmsg = NULL;
    struct lws_cache_msg_struct *n = NULL;
    char fpath[PNR_FILEPATH_MAXLEN+1] = {0};
    char *fname = "";
    char *p_sign = "";
    char *p_nonce = "";
    char *p_prikey = "";
    int msg_totallen = 0;
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    if(len <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:len(%d) err",len);
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql;
    }
    //id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey
    if (filepath) {
        ret = stat(filepath, &fstat);
        if (ret < 0) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get file stat err(%s-%d)", filepath, errno);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
        } else {
            filesize = fstat.st_size;
            DEBUG_PRINT(DEBUG_LEVEL_INFO, "get file size(%s-%d)", filepath, filesize);
        }
    }

	if (filename) {
        fname = filename;
    }

    if (ctype == PNR_MSG_CACHE_TYPE_TOX || ctype == PNR_MSG_CACHE_TYPE_TOXF) {
        userid = get_indexbytoxid(fromid);
        if (!userid) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get user(%s) index err", fromid);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
        }

		snprintf(fpath, sizeof(fpath), "/user%d/s/%s", userid, fname);
    } else {
        userid = get_indexbytoxid(toid);
        if (!userid) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get user(%s) index err", toid);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
        }

		snprintf(fpath, sizeof(fpath), "/user%d/r/%s", userid, fname);
    }
    if(filepath)
    {
        memset(fpath,0,PNR_FILEPATH_MAXLEN);
        if(strncmp(filepath,WS_SERVER_INDEX_FILEPATH,strlen(WS_SERVER_INDEX_FILEPATH)) == OK)
        {
            strcpy(fpath,filepath+strlen(WS_SERVER_INDEX_FILEPATH));
        }
        else
        {
            strcpy(fpath,filepath);
        }
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_msgcache_dbinsert_v3:renew fpath(%s)",fpath);
    }
    if (sign) {
        p_sign = sign;
    }
    
    if (nonce) {
        p_nonce = nonce;
    }
    
    if (prikey) {
        p_prikey = prikey;
    }

	if (logid) {
		snprintf(sql, MSGSQL_CMD_LEN, "select id from msg_tbl where fromid='%s' and logid=%d;",
			fromid, logid);
		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		ret = sqlite3_get_table(g_msgcachedb_handle[userid], sql, &dbResult, &nRow, &nColumn, &err);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", fromid, logid);
				sqlite3_free_table(dbResult);
                if(sql_malloc_flag == TRUE)
                {
                    free(p_sql);
                }  
                return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql err(%s)", sql);
			sqlite3_free(err);
            if(sql_malloc_flag == TRUE)
            {
                free(p_sql);
            }  
            return ERROR;
		}
	}
    
#if 0//换成直接插入方式    
    snprintf(sql, MSGSQL_CMD_LEN, "update msg_tbl set fromid='%s',"
		"toid='%s',type=%d,ctype=%d,msg='%s',len=%d,filename='%s',filepath='%s',"
		"filesize=%d,logid=%d,ftype=%d,skey='%s',dkey='%s' where id=%d;", 
		fromid, toid, type, ctype, pmsg, len, fname, fpath, filesize, 
		logid, ftype, p_newskey, p_newdkey, msgid);
#else
    //table msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey);
    if(sql_malloc_flag == TRUE)
    {
        snprintf(p_sql, MSGSQL_ALLOC_MAXLEN, "insert into msg_tbl "
            "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey)"
            "values(%d,'%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,%d,'%s','%s','%s');",
            msgid,fromid,toid,type,ctype,pmsg,len,fname,fpath,
            filesize,logid, ftype, p_sign, p_nonce, p_prikey);
    }
    else
    {
        snprintf(p_sql, MSGSQL_CMD_LEN, "insert into msg_tbl "
            "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey)"
            "values(%d,'%s','%s',%d,%d,'%s',%d,'%s','%s',%d,%d,%d,'%s','%s','%s');",
            msgid,fromid,toid,type,ctype,pmsg,len,fname,fpath,
            filesize,logid, ftype, p_sign, p_nonce, p_prikey);
    }
    
#endif
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)", p_sql);
    if (sqlite3_exec(g_msgcachedb_handle[userid], p_sql, 0, 0, &err)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", p_sql, err);
        sqlite3_free(err);
        if(sql_malloc_flag == TRUE)
        {
            free(p_sql);
        }  
        return ERROR;
    }
	
    msg_totallen = sizeof(struct lws_cache_msg_struct) + len + 1;
	msg = (struct lws_cache_msg_struct *)malloc(msg_totallen);
	if (!msg) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "malloc err!");
		return ERROR;
	}
    memset(msg, 0, msg_totallen);
    INIT_LIST_HEAD(&msg->list);
	msg->userid = userid;
	msg->msgid = msgid;
	msg->msglen = len;
	msg->timestamp = time(NULL);
    msg->type = type;
    msg->ctype = ctype;
    msg->ftype = ftype;
    msg->filesize = filesize;
    msg->logid = logid;
    msg->notice_flag = FALSE;
	strncpy(msg->msg, pmsg, len);
	strncpy(msg->fromid, fromid, TOX_ID_STR_LEN);
    strncpy(msg->toid, toid, TOX_ID_STR_LEN);
    strncpy(msg->filename, fname, UPLOAD_FILENAME_MAXLEN - 1);
    strncpy(msg->filepath, fpath, UPLOAD_FILENAME_MAXLEN*2 - 1);
    strncpy(msg->sign, p_sign, PNR_RSA_KEY_MAXLEN);
    strncpy(msg->nonce, p_nonce, PNR_RSA_KEY_MAXLEN);
    strncpy(msg->prikey, p_prikey, PNR_RSA_KEY_MAXLEN);
	pthread_mutex_lock(&lws_cache_msglock[userid]);
	if (!list_empty(&g_lws_cache_msglist[userid].list)) {
		list_for_each_safe(tmsg, n, &g_lws_cache_msglist[userid].list, struct lws_cache_msg_struct, list) {
			if (tmsg->logid && tmsg->logid == logid) {
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"msg cache repeat, no add");
                free(msg);
				goto OUT;
			}
		}
		
		list_for_each_safe(tmsg, n, &g_lws_cache_msglist[userid].list, struct lws_cache_msg_struct, list) {
			if (tmsg->msgid > msgid) {
				list_add_before(&msg->list, &tmsg->list);
				goto OUT;
			}
		}
	}
	list_add_tail(&msg->list, &g_lws_cache_msglist[userid].list);

OUT:
    pthread_mutex_unlock(&lws_cache_msglock[userid]);
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }  
    DEBUG_PRINT(DEBUG_LEVEL_INFO, "inset cache msg(%d:%s) len(%d)", userid, pmsg,len);    
	return OK;
}
/*****************************************************************************
 函 数 名  : pnr_msgcache_dbdelete
 功能描述  : 删除指定msgid的消息缓存
 输入参数  : int msgid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月15日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_dbdelete(int msgid, int userid)
{
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};
	struct lws_cache_msg_struct *msg = NULL;
	struct lws_cache_msg_struct *n = NULL;
    //cJSON *root = NULL;
    //cJSON *params = NULL;
    //cJSON *jmsg = NULL;

	snprintf(sql, MSGSQL_CMD_LEN, "delete from msg_tbl "
		"where id=%d;", msgid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)", sql);
    if (sqlite3_exec(g_msgcachedb_handle[userid], sql, 0, 0, &err)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql, err);
        sqlite3_free(err);
        return ERROR;
    }

    if (userid > PNR_IMUSER_MAXNUM) {
        return OK;
    }
	pthread_mutex_lock(&lws_cache_msglock[userid]);
	list_for_each_safe(msg, n, &g_lws_cache_msglist[userid].list, 
		struct lws_cache_msg_struct, list) {
		if (msg->msgid == msgid) {
			DEBUG_PRINT(DEBUG_LEVEL_INFO, "id(%d)-msgid(%d) ctype(%d) type(%d) del msg cache", 
				msg->userid, msg->msgid,msg->ctype,msg->type);
			list_del(&msg->list);
            switch (msg->ctype) {
            case PNR_MSG_CACHE_TYPE_LWS:
            case PNR_MSG_CACHE_TYPE_TOXA:
            case PNR_MSG_CACHE_TYPE_TOXAF:  
#if 0//现在不会在响应中写数据库，而是直接在发送的时候就写入了
                if (msg->type == PNR_IM_CMDTYPE_PUSHFILE
                    || msg->type == PNR_IM_CMDTYPE_PUSHFILE_TOX) {
                    /*DEBUG_PRINT(DEBUG_LEVEL_INFO,"PUSHFILE userid(%d) (%s->%s) (%s->%s) filename(%s,%s)",
                        msg->userid,msg->fromid,msg->toid,  msg->srckey, msg->dstkey,msg->filename,msg->filepath);*/
                    pnr_msglog_dbinsert(msg->userid, msg->ftype, msg->logid, MSG_STATUS_SENDOK,msg->fromid, 
                        msg->toid, msg->filename, msg->srckey, msg->dstkey, msg->filepath, msg->filesize);
                } else if (msg->type == PNR_IM_CMDTYPE_DELMSGPUSH) {
                    pnr_msglog_dbdelete(msg->userid, msg->ftype, msg->logid, msg->fromid,
                        msg->toid);
                }
                else if (msg->type == PNR_IM_CMDTYPE_PUSHMSG) {
                    root = cJSON_Parse(msg->msg);
                    if (root) {
                        params = cJSON_GetObjectItem(root, "params");
                        if (params) {
                            jmsg = cJSON_GetObjectItem(params, "Msg");
                            if (jmsg) {
                                pnr_msglog_dbinsert(msg->userid, msg->ftype,msg->logid,MSG_STATUS_SENDOK,
                                    msg->fromid, msg->toid, jmsg->valuestring, msg->srckey, msg->dstkey, NULL, 0);
                            } else {
                                DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get msg err");
                            }
                        } else {
                            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get paprams err");
                        }
                        cJSON_Delete(root);
                    } 
                    else {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get json root err");
                    }
                }
#endif
                break;

			case PNR_MSG_CACHE_TYPE_TOX:
				if (msg->type == PNR_IM_CMDTYPE_DELFRIENDPUSH) {
					int friendnum = GetFriendNumInFriendlist_new(g_tox_linknode[userid], msg->toid);
					if (friendnum >= 0) {
						tox_friend_delete(g_tox_linknode[userid], friendnum, NULL);
					}
				}

				pthread_mutex_lock(&g_imusr_array.usrnode[msg->userid].friends[msg->friendid].lock_sended);
				if (g_imusr_array.usrnode[msg->userid].friends[msg->friendid].sended == msg->msgid)
					g_imusr_array.usrnode[msg->userid].friends[msg->friendid].sended = 0;
				pthread_mutex_unlock(&g_imusr_array.usrnode[msg->userid].friends[msg->friendid].lock_sended);

				break;
            }
			
			free(msg);
            break;
		}
	}
    pthread_mutex_unlock(&lws_cache_msglock[userid]);

	return OK;
}

/*****************************************************************************
 函 数 名  : pnr_msgchache_dbdelete_by_logid
 功能描述  : 通过logid删除消息队列中的消息
 输入参数  : struct im_sendmsg_msgstruct *msg  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月29日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_dbdelete_by_logid(int index, struct im_sendmsg_msgstruct *msg)
{
	char **dbResult; 
    char *errmsg;
    int nRow = 0, nColumn = 0;
    int offset = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};
	int i = 0, n = 0;
	int ctype = 0;
	int userid = 0;
	struct lws_cache_msg_struct *cmsg = NULL;
    struct lws_cache_msg_struct *ctmp = NULL;
	struct lws_cache_msg_struct *smsg = NULL;
	File_Rcv *filercv = NULL;
	char filename[UPLOAD_FILENAME_MAXLEN];
	char filepath[UPLOAD_FILENAME_MAXLEN * 2];

	snprintf(sql_cmd, SQL_CMD_LEN, "select ctype,filename from msg_tbl where fromid=%s "
		"and toid=%s and logid=%d;", msg->fromuser_toxid, msg->touser_toxid, msg->log_id);
	if (sqlite3_get_table(g_msgcachedb_handle[index], sql_cmd, &dbResult, &nRow, 
            &nColumn, &errmsg) == SQLITE_OK) {
        offset = nColumn;
		
        for (i = 0; i < nRow ; i++) {
			memset(filename, 0, sizeof(filename));
			memset(filepath, 0, sizeof(filepath));
			
			ctype = atoi(dbResult[offset]);
			strncpy(filename, dbResult[offset + 1], UPLOAD_FILENAME_MAXLEN - 1);
			offset += nColumn;
			
			switch (ctype) {
			case PNR_MSG_CACHE_TYPE_TOX:
			case PNR_MSG_CACHE_TYPE_TOXF:
				userid = get_indexbytoxid(msg->fromuser_toxid);
		        if (!userid) {
		            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get from(%s) index err", msg->fromuser_toxid);
					continue;
				}
				break;

			default:
				userid = get_indexbytoxid(msg->touser_toxid);
		        if (!userid) {
		            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get to(%s) index err", msg->touser_toxid);
					continue;
				}
			}

			if (ctype == PNR_MSG_CACHE_TYPE_TOXF) {
				for (n = 0; n < NUM_FILE_SENDERS; n++) {
					smsg = file_senders[userid][n].msg;
					if (smsg && 
						!strcmp(msg->fromuser_toxid, smsg->fromid) && 
						!strcmp(msg->touser_toxid, smsg->toid) && 
						msg->log_id == smsg->logid) {
						memset(&file_senders[userid][n], 0, sizeof(File_Sender));
						break;
					}
				}
			} else {
				for (n = 0; n < NUM_FILE_SENDERS; n++) {
					filercv = &file_rcv[userid][n];
					if (filercv->filename[0] && !strcmp(filercv->filename, filename)) {
						fclose(filercv->file);
						memset(&file_rcv[userid][n], 0, sizeof(File_Rcv));
						snprintf(filepath, UPLOAD_FILENAME_MAXLEN * 2, 
							WS_SERVER_INDEX_FILEPATH"/usr%d/%s", userid, filename);
						unlink(filepath);
						break;
					}
				}
			}

			snprintf(sql_cmd, SQL_CMD_LEN, "delete from msg_tbl where fromid=%s "
				"and toid=%s and logid=%d;", msg->fromuser_toxid, msg->touser_toxid, msg->log_id);
			if (sqlite3_exec(g_msgcachedb_handle[index], sql_cmd, 0, 0, &errmsg)) {
		        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql_cmd, errmsg);
		        sqlite3_free(errmsg);
		    }
			pthread_mutex_lock(&lws_cache_msglock[userid]);
			if (!list_empty(&g_lws_cache_msglist[userid].list)) {
				list_for_each_safe(cmsg, ctmp, &g_lws_cache_msglist[userid].list, 
					struct lws_cache_msg_struct, list) {
					if (!strcmp(msg->fromuser_toxid, cmsg->fromid) && 
						!strcmp(msg->touser_toxid, cmsg->toid) && 
						msg->log_id == cmsg->logid) {
						list_del(&cmsg->list);
						free(cmsg);
					}
				}
			}
			pthread_mutex_unlock(&lws_cache_msglock[userid]);
		}

		sqlite3_free_table(dbResult);
	}

	return OK;
}

/*****************************************************************************
 函 数 名  : pnr_msgcache_dbdelete_nolock
 功能描述  : 无锁删除消息缓存
 输入参数  : int msgid   
             int userid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月24日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_dbdelete_nolock(struct lws_cache_msg_struct *msg)
{
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};

	snprintf(sql, MSGSQL_CMD_LEN, "delete from msg_tbl where id=%d;", msg->msgid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_msgcache_dbdelete_nolock:sql_cmd(%s)", sql);	
    if (sqlite3_exec(g_msgcachedb_handle[msg->userid], sql, 0, 0, &err)) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql, err);
        sqlite3_free(err);
        return ERROR;
    }

    DEBUG_PRINT(DEBUG_LEVEL_INFO, "id(%d)-msgid(%d) del msg cache", 
		msg->userid, msg->msgid);
    list_del(&msg->list);    
	free(msg);
	return OK;
}

/*****************************************************************************
 函 数 名  : pnr_msgcache_dbdelete_by_friendid
 功能描述  : 删除好友相关的消息缓存
 输入参数  : int index       
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
int pnr_msgcache_dbdelete_by_friendid(int index, char *friendid)
{	
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};
	struct lws_cache_msg_struct *cmsg = NULL;
    struct lws_cache_msg_struct *ctmp = NULL;

	snprintf(sql, SQL_CMD_LEN, "delete from msg_tbl where toid=%s;", friendid);
	if (sqlite3_exec(g_msgcachedb_handle[index], sql, 0, 0, &err)) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", sql, err);
		sqlite3_free(err);
	}
	pthread_mutex_lock(&lws_cache_msglock[index]);
	if (!list_empty(&g_lws_cache_msglist[index].list)) {
		list_for_each_safe(cmsg, ctmp, &g_lws_cache_msglist[index].list, struct lws_cache_msg_struct, list) {
			if (!strcmp(friendid, cmsg->toid)) {
				list_del(&cmsg->list);
				free(cmsg);
			}
		}
	}
	pthread_mutex_unlock(&lws_cache_msglock[index]);

	return 0;
}

/*****************************************************************************
 函 数 名  : pnr_msgcache_dbget
 功能描述  : 解析消息缓存数据
 输入参数  : void *obj        
             int cols         
             char **colval    
             char **colnames  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_dbget(void *obj, int colnum, char **colval, char **colnames)
{
	struct lws_cache_msg_struct *msg = NULL;
	struct lws_cache_msg_struct *tmsg = NULL;
    struct lws_cache_msg_struct *n = NULL;
	int len = 0;

	if (colnum < 12) {
		DEBUG_PRINT(DEBUG_LEVEL_INFO, "colume num err!(%d)", colnum);
		return OK;
	}

    //id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid
    for (int i = 0; i < colnum; i++) {
        if (!colval[i]) {
            DEBUG_PRINT(DEBUG_LEVEL_INFO, "colume item null!");
		    return OK;
        }
    }
	
	len = strtoul(colval[6], NULL, 0);
	if (len > 1400) {
		return OK;
	}

	msg = (struct lws_cache_msg_struct *)malloc(sizeof(*msg) + len + 1);
	if (!msg) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "malloc err!");
		return OK;
	}

    memset(msg, 0, sizeof(*msg));
	msg->msgid = strtoul(colval[0], NULL, 0);
    msg->type = strtoul(colval[3], NULL, 0);
    msg->ctype = strtoul(colval[4], NULL, 0);
    msg->filesize = strtoul(colval[9], NULL, 0);
    msg->logid = strtoul(colval[10], NULL, 0);
    msg->ftype = strtoul(colval[11], NULL, 0);
	msg->msglen = len;
	msg->timestamp = time(NULL);
    msg->notice_flag = TRUE; //重启后不推送
    memcpy(msg->fromid, colval[1], TOX_ID_STR_LEN);
    memcpy(msg->toid, colval[2], TOX_ID_STR_LEN);
	memcpy(msg->msg, colval[5], len);
    strncpy(msg->filename, colval[7], UPLOAD_FILENAME_MAXLEN - 1);
    strncpy(msg->filepath, colval[8], UPLOAD_FILENAME_MAXLEN*2 - 1);
#if (DB_CURRENT_VERSION < DB_VERSION_V3)
    strncpy(msg->srckey, colval[12], PNR_RSA_KEY_MAXLEN);
    strncpy(msg->dstkey, colval[13], PNR_RSA_KEY_MAXLEN);
#else
    strncpy(msg->sign, colval[12], PNR_RSA_KEY_MAXLEN);
    strncpy(msg->nonce, colval[13], PNR_RSA_KEY_MAXLEN);
    strncpy(msg->prikey, colval[14], PNR_RSA_KEY_MAXLEN);
#endif
    switch (msg->ctype) {
    case PNR_MSG_CACHE_TYPE_LWS:
    case PNR_MSG_CACHE_TYPE_TOXA:
    case PNR_MSG_CACHE_TYPE_TOXAF:
        msg->userid = get_indexbytoxid(msg->toid);
        if (!msg->userid) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get user(%s) index err!", msg->fromid);
    		return OK;
        }
        break;

    case PNR_MSG_CACHE_TYPE_TOX:
    case PNR_MSG_CACHE_TYPE_TOXF:
        msg->userid = get_indexbytoxid(msg->fromid);
        if (!msg->userid) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get user(%s) index err!", msg->fromid);
    		return OK;
        }
        break;

     default:
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "cache msg type(%d) err!", msg->type);
        return OK;
    }
	pthread_mutex_lock(&lws_cache_msglock[msg->userid]);
    if (!list_empty(&g_lws_cache_msglist[msg->userid].list)) {
		list_for_each_safe(tmsg, n, &g_lws_cache_msglist[msg->userid].list, struct lws_cache_msg_struct, list) {
			if (tmsg->logid && tmsg->logid == msg->logid) {
				goto OUT;
			}
		}
		
		list_for_each_safe(tmsg, n, &g_lws_cache_msglist[msg->userid].list, struct lws_cache_msg_struct, list) {
			if (tmsg->msgid > msg->msgid) {
				list_add_before(&msg->list, &tmsg->list);
				goto OUT;
			}
		}
	}
	list_add_tail(&msg->list, &g_lws_cache_msglist[msg->userid].list);

OUT:
    pthread_mutex_unlock(&lws_cache_msglock[msg->userid]);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d) add cached msg(%s)!", msg->userid, msg->msg);

	return OK;
}

/*****************************************************************************
 函 数 名  : pnr_msgcache_init
 功能描述  : 从数据库中初始化指定用户的消息缓存列表
 输入参数  : int userid  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_msgcache_init(void)
{
	char *err = NULL;
	char sql[SQL_CMD_LEN] = {0};
	int i = 0;


#if (DB_CURRENT_VERSION < DB_VERSION_V3)
    snprintf(sql, SQL_CMD_LEN, "select id,fromid,toid,type,ctype,"
        "msg,len,filename,filepath,filesize,logid,ftype,skey,dkey from msg_tbl;");
#else
    snprintf(sql, SQL_CMD_LEN, "select id,fromid,toid,type,ctype,"
        "msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey from msg_tbl;");
#endif
	for (i = 1; i <= PNR_IMUSER_MAXNUM; i++) 
    {
        if(g_msgcachedb_handle[i])
        {
    		if (sqlite3_exec(g_msgcachedb_handle[i], sql, pnr_msgcache_dbget, NULL, &err)) {
    			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql cmd(%s) err(%s)", sql, err);
    			sqlite3_free(err);
    		}
        }
	}
    return OK;
}

/***********************************************************************************
  Function:      pnr_filelog_delete_byid
  Description:  根据msgid删除文件及文件记录
  Calls:
  Called By:     
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelog_delete_byid(int msgid,char* user_id,char* friend_id)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    char filepath[PNR_FILEPATH_MAXLEN+1] = {0};
    char sys_cmd[SQL_CMD_LEN] = {0};
    struct db_string_ret db_ret;
	int index = 0;
	
    if(msgid == 0)
    {
        return ERROR;
    }

    db_ret.buf_len = PNR_FILEPATH_MAXLEN;
    db_ret.pbuf = filepath;
    snprintf(sql_cmd,SQL_CMD_LEN,"select ext from msg_tbl where logid=%d;",msgid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_filelog_delete_byid:sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_singstr_result,&db_ret,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }

    if(access(filepath,F_OK) == OK)
    {
        //这里涉及到删除文件，需要先检测下删除目录的合法性
        if(strncasecmp(filepath,DAEMON_PNR_USERDATA_DIR,strlen(DAEMON_PNR_USERDATA_DIR)) == OK)
        {
            snprintf(sys_cmd,SQL_CMD_LEN,"rm -f %s",filepath);
            system(sys_cmd);
            DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"pnr_filelog_delete_byid file delete:%s",filepath);
        }
    }
    //删除对应消息记录
    pnr_msglog_dbdelete(0,PNR_IM_MSGTYPE_FILEALL,0,user_id,friend_id);
    return OK;
}


/**********************************************************************************
  Function:      pnr_del_filelog_dbcallback
  Description:   删除文件记录的数据库回掉处理
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_del_filelog_dbcallback(void* obj, int n_columns, char** column_values,char** column_names)
{
    int msgid = 0;
    struct im_sendmsg_msgstruct* pmsg = NULL;
    char* p_file = NULL;
    char sys_cmd[SQL_CMD_LEN] = {0};
    if(n_columns < 2)
    {
        return ERROR;
    }
    pmsg = (struct im_sendmsg_msgstruct*)obj;
	if(column_values[0] != NULL)
	{
	    msgid = atoi(column_values[0]);  
    }
    else
    {
        return ERROR;
    }
	if(column_values[1] != NULL)
	{
        p_file = column_values[1];
    }
    else
    {
        return ERROR;
    }
    if(access(p_file,F_OK) == OK)
    {
        //这里涉及到删除文件，需要先检测下删除目录的合法性
        if(strncasecmp(p_file,DAEMON_PNR_USERDATA_DIR,strlen(DAEMON_PNR_USERDATA_DIR)) == OK)
        {
            snprintf(sys_cmd,SQL_CMD_LEN,"rm -f %s",p_file);
            system(sys_cmd);
            DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"pnr_del_filelog_dbcallback file delete:%s",p_file);
        }
    }

    //删除对应消息记录
    pnr_msglog_dbdelete(msgid,pmsg->msgtype,0,pmsg->fromuser_toxid,pmsg->touser_toxid);
    return OK;
}

/***********************************************************************************
  Function:      pnr_filelog_delete_byfiletype
  Description:  根据文件类型删除文件及文件记录
  Calls:
  Called By:     
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelog_delete_byfiletype(int filetype,char* user_id,char* friend_id)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    char filepath[PNR_FILEPATH_MAXLEN+1] = {0};
    char sys_cmd[SQL_CMD_LEN] = {0};
    char **dbResult; 
    int nRow, nColumn;
    int i,offset,msgid = 0;
	int userindex = 0;

	userindex = get_indexbytoxid(user_id);
	if (!userindex) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "not found user(%s)", user_id);
		return ERROR;
	}

    switch(filetype)
    {
        //仅仅删除聊天消息
        case PNR_IM_MSGTYPE_TEXT:
            pnr_msglog_dbdelete(userindex,filetype,0,user_id,friend_id);
            break;  
        //删除某一类型的文件记录
        case PNR_IM_MSGTYPE_IMAGE:
        case PNR_IM_MSGTYPE_AUDIO:
        case PNR_IM_MSGTYPE_MEDIA:
        case PNR_IM_MSGTYPE_FILE:
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,ext from msg_tbl where from_user='%s' and to_user='%s' and msgtype=%d;",
                user_id,friend_id,filetype);
            if(sqlite3_get_table(g_msglogdb_handle[userindex], sql_cmd, &dbResult, &nRow, 
                    &nColumn, &errMsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow ; i++ )
                {               
                    memset(filepath,0,PNR_FILEPATH_MAXLEN);
                    msgid = atoi(dbResult[offset]);
                    strcpy(filepath,dbResult[offset+1]);
                    if(access(filepath,F_OK) == OK)
                    {
                        //这里涉及到删除文件，需要先检测下删除目录的合法性
                        if(strncasecmp(filepath,PNR_DB_USERFILE_HEAD,strlen(PNR_DB_USERFILE_HEAD)) == OK)
                        {
                            snprintf(sys_cmd,SQL_CMD_LEN,"rm -f %s",filepath);
                            system(sys_cmd);
                            DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"pnr_filelog_delete_byfiletype file delete:%s",filepath);
                        }
                    }
                    snprintf(sql_cmd,SQL_CMD_LEN,"delete from msg_tbl where id=%d",msgid);
                    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
                        sqlite3_free(errMsg);
                    }
                    offset += nColumn;
                 }
                //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
                sqlite3_free_table(dbResult);
            }
            break;
        case PNR_IM_MSGTYPE_FILEALL:
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,ext from msg_tbl where from_user='%s' and to_user='%s'"
                " and (msgtype=%d or msgtype=%d or msgtype=%d or msgtype=%d);",user_id,friend_id,
                PNR_IM_MSGTYPE_IMAGE,PNR_IM_MSGTYPE_AUDIO,PNR_IM_MSGTYPE_MEDIA,PNR_IM_MSGTYPE_FILE);
            if(sqlite3_get_table(g_msglogdb_handle[userindex], sql_cmd, &dbResult, &nRow, 
                    &nColumn, &errMsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow ; i++ )
                {               
                    memset(filepath,0,PNR_FILEPATH_MAXLEN);
                    msgid = atoi(dbResult[offset]);
                    strcpy(filepath,dbResult[offset+1]);
                    if(access(filepath,F_OK) == OK)
                    {
                        //这里涉及到删除文件，需要先检测下删除目录的合法性
                        if(strncasecmp(filepath,PNR_DB_USERFILE_HEAD,strlen(PNR_DB_USERFILE_HEAD)) == OK)
                        {
                            snprintf(sys_cmd,SQL_CMD_LEN,"rm -f %s",filepath);
                            system(sys_cmd);
                            DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"pnr_filelog_delete_byfiletype file delete:%s",filepath);
                        }
                    }
                    snprintf(sql_cmd,SQL_CMD_LEN,"delete from msg_tbl where id=%d",msgid);
                    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,0,0,&errMsg))
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
                        sqlite3_free(errMsg);
                    }
                    offset += nColumn;
                 }
                //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
                sqlite3_free_table(dbResult);
            }
            break;
        case PNR_IM_MSGTYPE_ALL:
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,ext from msg_tbl where ((from_user='%s' and to_user='%s')"
				" or (from_user='%s' and to_user='%s'))"
				" and msgtype in (%d,%d,%d,%d);",user_id,friend_id,friend_id,user_id,
                PNR_IM_MSGTYPE_IMAGE,PNR_IM_MSGTYPE_AUDIO,PNR_IM_MSGTYPE_MEDIA,PNR_IM_MSGTYPE_FILE);
            if(sqlite3_get_table(g_msglogdb_handle[userindex], sql_cmd, &dbResult, &nRow, 
                    &nColumn, &errMsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow ; i++ )
                {               
                    memset(filepath,0,PNR_FILEPATH_MAXLEN);
                    msgid = atoi(dbResult[offset]);
                    strcpy(filepath,dbResult[offset+1]);
                    if(access(filepath,F_OK) == OK)
                    {
                        //这里涉及到删除文件，需要先检测下删除目录的合法性
                        if(strncasecmp(filepath,PNR_DB_USERFILE_HEAD,strlen(PNR_DB_USERFILE_HEAD)) == OK)
                        {
                            snprintf(sys_cmd,SQL_CMD_LEN,"rm -f %s",filepath);
                            system(sys_cmd);
                            DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"pnr_filelog_delete_byfiletype file delete:%s",filepath);
                        }
                    }
                    snprintf(sql_cmd,SQL_CMD_LEN,"delete from msg_tbl where id=%d",msgid);
                    if(sqlite3_exec(g_msglogdb_handle[userindex],sql_cmd,0,0,&errMsg))
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
                        sqlite3_free(errMsg);
                    }
                    offset += nColumn;
                 }
                //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
                sqlite3_free_table(dbResult);
            }
            pnr_msglog_dbdelete(userindex,PNR_IM_MSGTYPE_TEXT,0,user_id,friend_id);
            break;
    }
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_account_init_fromdb
 功能描述  : 从数据库中初始化指定用户的账户信息
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_init_fromdb(void)
{
	int8* errMsg = NULL;
	char sql[SQL_CMD_LEN] = {0};
    char **dbResult; 
    int nRow = 0, nColumn = 0;;
    int i,offset,tmpid = 0;
    int temp_usertype = 0;
    int userindex= 0;
    struct db_string_ret db_ret;

    memset(&g_account_array,0,sizeof(g_account_array));
    //获取tmp usn信息
    db_ret.buf_len = PNR_USN_MAXLEN;
    db_ret.pbuf = g_account_array.temp_user_sn;
	snprintf(sql,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_TEMPACCOUNT_USN_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql,dbget_singstr_result,&db_ret,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"pnr_server start!!!get temp account usn %s",g_account_array.temp_user_sn);
    //获取账户信息
	snprintf(sql, SQL_CMD_LEN, "select type,active,identifycode,mnemonic,usersn,"
                "userindex,nickname,loginkey,toxid,pubkey,lastactive,createtime from user_account_tbl;");
    if(sqlite3_get_table(g_db_handle, sql, &dbResult, &nRow, &nColumn, &errMsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow ; i++ )
        {           
            temp_usertype = atoi(dbResult[offset]);
            switch(temp_usertype)
            {
                case PNR_USER_TYPE_ADMIN:
                    tmpid = g_account_array.total_user_num+1;
                    if(tmpid > PNR_IMUSER_MAXNUM)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_account_init:admin_user_num out");
                        sqlite3_free_table(dbResult);
                        return ERROR;
                    }
                    g_account_array.admin_user_num++;
                    g_account_array.total_user_num++;
                    g_account_array.account[tmpid].type = temp_usertype;
                    g_account_array.account[tmpid].active = atoi(dbResult[offset+1]);
                    strncpy(g_account_array.account[tmpid].identifycode,dbResult[offset+2],PNR_IDCODE_MAXLEN);
                    //不是normal账号没有助记符
                    strncpy(g_account_array.account[tmpid].user_sn,dbResult[offset+4],PNR_USN_MAXLEN);
                    if(g_account_array.account[tmpid].active == TRUE)
                    {
                        userindex = atoi(dbResult[offset+5]);
                        strncpy(g_account_array.account[tmpid].nickname,dbResult[offset+6],PNR_USERNAME_MAXLEN);
                        strncpy(g_account_array.account[tmpid].loginkey,dbResult[offset+7],PNR_LOGINKEY_MAXLEN);
                        strncpy(g_account_array.account[tmpid].toxid,dbResult[offset+8],TOX_ID_STR_LEN);
                        strncpy(g_account_array.account[tmpid].user_pubkey,dbResult[offset+9],PNR_USER_PUBKEY_MAXLEN);
                    }
                    g_account_array.account[tmpid].lastactive = atoi(dbResult[offset+10]);
                    g_account_array.account[tmpid].createtime= atoi(dbResult[offset+11]);
                    break;
                case PNR_USER_TYPE_NORMAL:
                    tmpid = g_account_array.total_user_num+1;
                    if(tmpid > PNR_IMUSER_MAXNUM)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_account_init:normal_user_num out");
                        sqlite3_free_table(dbResult);
                        return ERROR;
                    }
                    g_account_array.normal_user_num++;
                    g_account_array.total_user_num++;
                    g_account_array.account[tmpid].type = temp_usertype;
                    g_account_array.account[tmpid].active = atoi(dbResult[offset+1]);
                    strncpy(g_account_array.account[tmpid].identifycode,dbResult[offset+2],PNR_IDCODE_MAXLEN);
                    strncpy(g_account_array.account[tmpid].mnemonic,dbResult[offset+3],PNR_USERNAME_MAXLEN);
                    strncpy(g_account_array.account[tmpid].user_sn,dbResult[offset+4],PNR_USN_MAXLEN);
                    if(g_account_array.account[tmpid].active == TRUE)
                    {
                        userindex = atoi(dbResult[offset+5]);
                        strncpy(g_account_array.account[tmpid].nickname,dbResult[offset+6],PNR_USERNAME_MAXLEN);
                        strncpy(g_account_array.account[tmpid].loginkey,dbResult[offset+7],PNR_LOGINKEY_MAXLEN);
                        strncpy(g_account_array.account[tmpid].toxid,dbResult[offset+8],TOX_ID_STR_LEN);
                        strncpy(g_account_array.account[tmpid].user_pubkey,dbResult[offset+9],PNR_USER_PUBKEY_MAXLEN);
                    }    
                    g_account_array.account[tmpid].lastactive = atoi(dbResult[offset+10]);
                    g_account_array.account[tmpid].createtime= atoi(dbResult[offset+11]);
                    break;
                case PNR_USER_TYPE_TEMP:
                    tmpid = g_account_array.total_user_num+1;
                    if(tmpid > PNR_IMUSER_MAXNUM)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_account_init:normal_user_num out");
                        sqlite3_free_table(dbResult);
                        return ERROR;
                    }
                    g_account_array.temp_user_num++;
                    g_account_array.total_user_num++;
                    g_account_array.account[tmpid].type = temp_usertype;
                    g_account_array.account[tmpid].active = atoi(dbResult[offset+1]);
                    strncpy(g_account_array.account[tmpid].identifycode,dbResult[offset+2],PNR_IDCODE_MAXLEN);
                    //strncpy(g_account_array.temp_account[tmpid].mnemonic,dbResult[offset+3],PNR_USERNAME_MAXLEN);
                    strncpy(g_account_array.account[tmpid].user_sn,dbResult[offset+4],PNR_USN_MAXLEN);
                    if(g_account_array.account[tmpid].active == TRUE)
                    {
                        userindex = atoi(dbResult[offset+5]);
                        strncpy(g_account_array.account[tmpid].nickname,dbResult[offset+6],PNR_USERNAME_MAXLEN);
                        strncpy(g_account_array.account[tmpid].loginkey,dbResult[offset+7],PNR_LOGINKEY_MAXLEN);
                        strncpy(g_account_array.account[tmpid].toxid,dbResult[offset+8],TOX_ID_STR_LEN);
                        strncpy(g_account_array.account[tmpid].user_pubkey,dbResult[offset+9],PNR_USER_PUBKEY_MAXLEN);
                    }   
                    g_account_array.account[tmpid].lastactive = atoi(dbResult[offset+10]);
                    g_account_array.account[tmpid].createtime= atoi(dbResult[offset+11]);
                    break;
                default:
                    break;
            }
            if(userindex > 0 && userindex <= PNR_IMUSER_MAXNUM)
            {
                g_account_array.account[tmpid].index = userindex;
                if(g_account_array.account[tmpid].active == TRUE)
                {
                    strcpy(g_imusr_array.usrnode[userindex].user_nickname,g_account_array.account[tmpid].nickname);
                    strcpy(g_imusr_array.usrnode[userindex].user_toxid,g_account_array.account[tmpid].toxid);
                    strcpy(g_imusr_array.usrnode[userindex].user_pubkey,g_account_array.account[tmpid].user_pubkey);
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"###get user(%d) user_toxid(%s) nickname(%s)",
                        userindex,g_imusr_array.usrnode[userindex].user_toxid,g_imusr_array.usrnode[userindex].user_nickname);
                }
            }
            offset += nColumn;
         }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbinsert
 功能描述  : 数据库插入一个新的用户账号
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbinsert(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_account == NULL)
    {
        return ERROR;
    }
    //这里对admin账户和temp账户，添加默认助记符
    if(strlen(p_account->mnemonic) <= 0)
    {
        switch(p_account->type)
        {
            case PNR_USER_TYPE_ADMIN:
                strcpy(p_account->mnemonic,PNR_ADMINUSER_MNEMONIC);
                break;
            case PNR_USER_TYPE_NORMAL:
                strcpy(p_account->mnemonic,PNR_NORMALUSER_MNEMONIC);
                break;
            case PNR_USER_TYPE_TEMP:
                strcpy(p_account->mnemonic,PNR_TEMPUSER_MNEMONIC);
                break;
            default:
                break;
        }
    }
    //id,lastactive,type,active,identifycode,mnemonic,usersn,userindex,nickname,loginkey,toxid,pubkey,info,extinfo
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into user_account_tbl values(null,0,%d,%d,'%s','%s','%s',0,'','','','','','',0);",
             p_account->type,p_account->active,p_account->identifycode,p_account->mnemonic,p_account->user_sn);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_usrdev_mappinginfo_dbget
  Description:   数据库查询toxid与从属路由器对应关系
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_usrdev_mappinginfo_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 4)
    {
        return ERROR;
    }
	struct im_userdev_mapping_struct* p_info = (struct im_userdev_mapping_struct*)obj;
    if(p_info == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_usrdev_mappinginfo_dbget obj is null");
        return ERROR;
    }
    p_info->id = atoi(column_values[0]);
    p_info->userindex= atoi(column_values[1]);
    strncpy(p_info->user_devid,column_values[2],TOX_ID_STR_LEN);
    strncpy(p_info->user_devname,column_values[3],PNR_USERNAME_MAXLEN);    
	return OK;
}
/**********************************************************************************
  Function:      pnr_usrdev_mappinginfo_sqlget
  Description:   数据库查询toxid与从属路由器对应关系
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_usrdev_mappinginfo_sqlget(struct im_userdev_mapping_struct* p_info)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    if(p_info == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_usrdev_mappinginfo_dbget obj is null");
        return ERROR;
    }
	snprintf(sql_cmd, SQL_CMD_LEN, "select id,userindex,devid,devname from userdev_mapping_tbl where usrid='%s';",p_info->user_toxid);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_usrdev_mappinginfo_sqlget: sql(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,pnr_usrdev_mappinginfo_dbget,p_info,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }   
	return OK;
}
/***********************************************************************************
  Function:      pnr_userdev_mapping_dbupdate
  Description:  更新用户和设备对应关系信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_userdev_mapping_dbupdate(char* user_id,char* dev_id,char* dev_name)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    int change_flag = FALSE;
    int index =0;
    struct im_userdev_mapping_struct user;

    if (user_id == NULL || dev_id == NULL || dev_name == NULL) 
    {
        return ERROR;
    }
    memset(&user,0,sizeof(user));
    strcpy(user.user_toxid,user_id);
    //"create table userdev_mapping_tbl(id integer primary key autoincrement,userindex,usrid,devid,devname);"
	snprintf(sql_cmd, SQL_CMD_LEN, "select id,userindex,devid,devname from userdev_mapping_tbl where usrid='%s';",user.user_toxid);
    if(sqlite3_exec(g_db_handle,sql_cmd,pnr_usrdev_mappinginfo_dbget,&user,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(user.id == 0)
    {
        index = get_indexbytoxid(user.user_toxid);
        //新记录，插入
        memset(sql_cmd,0,SQL_CMD_LEN);
        snprintf(sql_cmd, SQL_CMD_LEN, "insert into userdev_mapping_tbl values(NULL,%d,'%s','%s','%s');",
            index,user.user_toxid,dev_id,dev_name);
        change_flag = TRUE;
    }
    else
    {
        if((strcmp(user.user_devid,dev_id) != OK) || (strcmp(user.user_devname,dev_name) != OK))
        {
            memset(sql_cmd,0,SQL_CMD_LEN);
            snprintf(sql_cmd, SQL_CMD_LEN, "update userdev_mapping_tbl set devid='%s',devname='%s' where usrid='%s';",
                dev_id,dev_name,user.user_toxid);
            change_flag = TRUE;
        }
    }
    if(change_flag == TRUE)
    {
    	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_userdev_mapping_dbupdate:sql_cmd(%s)",sql_cmd);
        if (sqlite3_exec(g_db_handle, sql_cmd, 0, 0, &errMsg)) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
            sqlite3_free(errMsg);
            return ERROR;
        }    
    }    
    return OK;
}
/***********************************************************************************
  Function:      pnr_userdev_mapping_dbupdate_bydevid
  Description:  更新用户和设备对应关系信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_userdev_mapping_dbupdate_bydevid(char* dev_id,char* dev_name)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    if (dev_id == NULL || dev_name == NULL) 
    {
        return ERROR;
    }
    memset(sql_cmd,0,SQL_CMD_LEN);
    snprintf(sql_cmd, SQL_CMD_LEN, "update userdev_mapping_tbl set devname='%s' where devid='%s';",
        dev_name,dev_id);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_userdev_mapping_dbupdate_bydevid:sql_cmd(%s)",sql_cmd);
    if (sqlite3_exec(g_db_handle, sql_cmd, 0, 0, &errMsg)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }    
    return OK;
}
/***********************************************************************************
  Function:      pnr_userdev_mapping_dbdelte_byusrid
  Description:  根据用户toxid删除用户和设备对应关系信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_userdev_mapping_dbdelte_byusrid(char* usrid)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    if (usrid == NULL) 
    {
        return ERROR;
    }
    memset(sql_cmd,0,SQL_CMD_LEN);
    snprintf(sql_cmd, SQL_CMD_LEN, "delete from userdev_mapping_tbl where usrid='%s';",usrid);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "pnr_userdev_mapping_dbdelte_byusrid:sql_cmd(%s)",sql_cmd);
    if (sqlite3_exec(g_db_handle, sql_cmd, 0, 0, &errMsg)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }    
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_account_tmpuser_dbinsert
 功能描述  : 数据库插入一个新的临时用户账号
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_tmpuser_dbinsert(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_account == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into user_account_tbl values(null,0,%d,%d,'%s','%s','%s',%d,'%s','%s','%s','','','%s',%d);",
             p_account->type,p_account->active,p_account->identifycode,p_account->mnemonic,p_account->user_sn,
             p_account->index,p_account->nickname,p_account->loginkey,p_account->toxid,p_account->user_pubkey,(int)time(NULL));
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_account_dbupdate
 功能描述  : 数据库跟新一个新的用户信息
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbupdate(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(p_account == NULL)
    {
        return ERROR;
    }
    if(p_account->type == PNR_USER_TYPE_TEMP)
    {
        //id,lastactive,type,active,identifycode,mnemonic,usersn,userindex,nickname,loginkey,toxid,pubkey,info,extinfo
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into user_account_tbl values(null,%d,%d,%d,'%s','%s','%s',%d,'%s','%s','%s','','','%s',%d);",
                 (int)time(NULL),p_account->type,p_account->active,p_account->identifycode,p_account->mnemonic,p_account->user_sn,
                 p_account->index,p_account->nickname,p_account->loginkey,p_account->toxid,p_account->user_pubkey,(int)time(NULL));
    }
    else
    {
    	snprintf(sql_cmd,SQL_CMD_LEN,"update user_account_tbl set lastactive=%d,type=%d,active=%d,identifycode='%s',mnemonic='%s',"
            "userindex=%d,nickname='%s',loginkey='%s',toxid='%s',pubkey='%s',createtime=%d where usersn='%s';",
            (int)time(NULL),p_account->type,p_account->active,p_account->identifycode,p_account->mnemonic,p_account->index,
            p_account->nickname,p_account->loginkey,p_account->toxid,p_account->user_pubkey,(int)time(NULL),p_account->user_sn);    
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbupdate(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbupdate_idcode_byusn
 功能描述  : 根据usn修改idcode
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbupdate_idcode_byusn(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(p_account == NULL)
    {
        return ERROR;
    }
    if(p_account->type == PNR_USER_TYPE_TEMP)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbupdate_idcode_byusn:tmp user");
        return ERROR;
    }
    else
    {
    	snprintf(sql_cmd,SQL_CMD_LEN,"update user_account_tbl set identifycode='%s' where usersn='%s';",
            p_account->identifycode,p_account->user_sn);    
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbupdate_idcode_byusn(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_account_dbupdate_bytoxid
 功能描述  : 数据库跟新一个新的用户信息
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbupdate_bytoxid(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(p_account == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"update user_account_tbl set lastactive=%d,type=%d,active=%d,identifycode='%s',mnemonic='%s',"
        "userindex=%d,nickname='%s',loginkey='%s',pubkey='%s' where toxid='%s';",
        (int)time(NULL),p_account->type,p_account->active,p_account->identifycode,p_account->mnemonic,
        p_account->index,p_account->nickname,p_account->loginkey,p_account->user_pubkey,p_account->toxid);    
    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbupdate_bytoxid(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbupdate_dbinfo_bytoxid
 功能描述  : 数据库跟新一个账户相关用户信息
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbupdate_dbinfo_bytoxid(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(p_account == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd,SQL_CMD_LEN,"update user_account_tbl set nickname='%s' where toxid='%s';",
        p_account->nickname,p_account->toxid);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbupdate_dbinfo_bytoxid(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbupdate_lastactive_bytoxid
 功能描述  : 数据库跟新一个新的用户最后活动时间
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbupdate_lastactive_bytoxid(char* p_toxid)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_toxid == NULL)
    {
        return ERROR;
    }

	snprintf(sql_cmd,SQL_CMD_LEN,"update user_account_tbl set lastactive=%d where toxid='%s';",
        (int)time(NULL),p_toxid);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbupdate_lastactive_bytoxid(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      pnr_usr_account_dbget
  Description:   数据库查询账号类别操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_usr_account_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 10)
    {
        return ERROR;
    }
	struct pnr_account_struct* p_account = (struct pnr_account_struct*)obj;
    if(p_account == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_usr_account_dbget obj is null");
        return ERROR;
    }
    p_account->dbid = atoi(column_values[0]);
    p_account->lastactive = atoi(column_values[1]);
    p_account->type = atoi(column_values[2]);
    p_account->active = atoi(column_values[3]);
    strncpy(p_account->identifycode,column_values[4],PNR_IDCODE_MAXLEN);
    strncpy(p_account->mnemonic,column_values[5],PNR_USERNAME_MAXLEN);
    strncpy(p_account->user_sn,column_values[6],PNR_USN_MAXLEN);
    if(p_account->active == TRUE)
    {
        p_account->index = atoi(column_values[7]);
        strncpy(p_account->nickname,column_values[8],PNR_USERNAME_MAXLEN);
        strncpy(p_account->loginkey,column_values[9],PNR_LOGINKEY_MAXLEN);
        strncpy(p_account->toxid,column_values[10],TOX_ID_STR_LEN);
        strncpy(p_account->user_pubkey,column_values[11],PNR_USER_PUBKEY_MAXLEN);
    } 
    p_account->createtime = atoi(column_values[12]);
	return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbcheck_bypubkey
 功能描述  : 根据检查是否有重复的账号和pubkey
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbcheck_bypubkey(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    int count = 0;
    if(p_account == NULL)
    {
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from user_account_tbl where usersn='%s' and pubkey='%s';",
            p_account->user_sn,p_account->user_pubkey);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbcheck_bypubkey user(%s:%s) pubkey exsit",p_account->user_sn,p_account->user_pubkey);
        return ERROR;
    }  
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbget_byusn
 功能描述  : 根据usn查找对应账号信息
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_get_byusn(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_account == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd, SQL_CMD_LEN, "select id,lastactive,type,active,identifycode,mnemonic,usersn,"
                "userindex,nickname,loginkey,toxid,pubkey,createtime from user_account_tbl where usersn='%s';",p_account->user_sn);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_get_byusn:sqlite cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,pnr_usr_account_dbget,p_account,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_get_byusn:get active(%d) by sn(%s)",p_account->active,p_account->user_sn);
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbget_byuserkey
 功能描述  : 根据pubkey查找对应账号信息
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbget_byuserkey(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_account == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd, SQL_CMD_LEN, "select id,lastactive,type,active,identifycode,mnemonic,usersn,"
                "userindex,nickname,loginkey,toxid,pubkey,createtime from user_account_tbl where pubkey='%s';",p_account->user_pubkey);
    if(sqlite3_exec(g_db_handle,sql_cmd,pnr_usr_account_dbget,p_account,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbget_byuserkey:get active(%d) by pubkey(%s)",p_account->active,p_account->user_pubkey);
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbget_byuserid
 功能描述  : 根据userid查找对应账号信息
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbget_byuserid(struct pnr_account_struct* p_account)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_account == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd, SQL_CMD_LEN, "select id,lastactive,type,active,identifycode,mnemonic,usersn,"
                "userindex,nickname,loginkey,toxid,pubkey,createtime from user_account_tbl where toxid='%s';",p_account->toxid);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbget_byuserid:sqlite cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,pnr_usr_account_dbget,p_account,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_account_dbget_byuserid:get active(%d) by toxid(%s)",p_account->active,p_account->toxid);
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_account_dbdelete_byuserid
 功能描述  : 根据userid删除对应账号信息
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_account_dbdelete_byuserid(char* userid)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(userid == NULL)
    {
        return ERROR;
    }
	snprintf(sql_cmd, SQL_CMD_LEN, "delete from user_account_tbl where toxid='%s';",userid);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_userinfo_dbget
  Description:   数据库查询用户信息操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_userinfo_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 8)
    {
        return ERROR;
    }
	struct pnr_userinfo_struct* p_user = (struct pnr_userinfo_struct*)obj;
    if(p_user == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_userinfo_dbget obj is null");
        return ERROR;
    }
    p_user->id = atoi(column_values[0]);
    p_user->index = atoi(column_values[1]);
    p_user->local = atoi(column_values[2]);
    if(column_values[3] != NULL)
    {
        strncpy(p_user->userid,column_values[3],TOX_ID_STR_LEN);
    }
    if(column_values[4] != NULL)
    {
        strncpy(p_user->devid,column_values[4],TOX_ID_STR_LEN);
    }
    if(column_values[5] != NULL)
    {
        strncpy(p_user->avatar,column_values[5],PNR_FILENAME_MAXLEN);
    }
    if(column_values[6] != NULL)
    {
        strncpy(p_user->md5,column_values[6],PNR_MD5_VALUE_MAXLEN);
    }
    if(column_values[7] != NULL)
    {
        strncpy(p_user->info,column_values[7],USERINFO_MAXLEN);
    } 
	return OK;
}
/*****************************************************************************
 函 数 名  : pnr_userinfo_dbget_byuserid
 功能描述  : 根据userid查找对应用户信息
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_userinfo_dbget_byuserid(struct pnr_userinfo_struct* puser)
{
    int8* errMsg = NULL;
    char sql_cmd[CMD_MAXLEN] = {0};

    if(puser == NULL)
    {
        return ERROR;
    }
    //table userinfo_tbl(id integer primary key autoincrement,userindex,local,usrid,devid,avatar,md5,info);"
	snprintf(sql_cmd, CMD_MAXLEN, "select id,userindex,local,usrid,devid,avatar,md5,info from userinfo_tbl where usrid='%s';",puser->userid);
    if(sqlite3_exec(g_db_handle,sql_cmd,pnr_userinfo_dbget,puser,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_userinfo_dbupdate
 功能描述  : 更新用户信息
 输入参数  : userinfo
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_userinfo_dbupdate(struct pnr_userinfo_struct* puser)
{
    int8* errMsg = NULL;
    char sql_cmd[CMD_MAXLEN] = {0};
    int count = 0;
    if(puser == NULL)
    {
        return ERROR;
    }
    if(strlen(puser->userid) != TOX_ID_STR_LEN)
    {
        return ERROR;
    }
    //这里要检查一下，区别是插入还是更新
    snprintf(sql_cmd,CMD_MAXLEN,"select count(*) from userinfo_tbl where usrid='%s';",puser->userid);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    memset(sql_cmd,0,CMD_MAXLEN);
    //table userinfo_tbl(id integer primary key autoincrement,userindex,local,usrid,devid,avatar,md5,info);"
    if(count > 0)
    {
        snprintf(sql_cmd, CMD_MAXLEN, "update userinfo_tbl set userindex=%d,local=%d,devid='%s',avatar='%s',md5='%s',info='%s' where usrid='%s';",
            puser->index,puser->local,puser->devid,puser->avatar,puser->md5,puser->info,puser->userid);
    }      
    else
    {
        snprintf(sql_cmd, CMD_MAXLEN, "insert into userinfo_tbl "
            "(id,userindex,local,usrid,devid,avatar,md5,info) "
            "values(null,%d,%d,'%s','%s','%s','%s','%s');",
            puser->index,puser->local,puser->userid,puser->devid,puser->avatar,puser->md5,puser->info);
    }
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_userinfo_dbdelete_byuserid
 功能描述  : 根据userid删除对应用户信息
 输入参数  : account
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_userinfo_dbdelete_byuserid(char* usrid)
{
    int8* errMsg = NULL;
    char sql_cmd[CMD_MAXLEN] = {0};

    if(usrid == NULL)
    {
        return ERROR;
    }
    //table userinfo_tbl(id integer primary key autoincrement,userindex,local,usrid,devid,avatar,md5,info);"
	snprintf(sql_cmd, CMD_MAXLEN, "delete from userinfo_tbl where usrid='%s';",usrid);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_tox_datafile_dbget
  Description:   数据库查询实例类别操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_tox_datafile_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 7)
    {
        return ERROR;
    }
	struct pnr_tox_datafile_struct *pdatainfo = (struct pnr_tox_datafile_struct*)obj;
    if(pdatainfo == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_tox_datafile_dbget obj is null");
        return ERROR;
    }
    /*id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile*/
    pdatainfo->dbid = atoi(column_values[0]);
    pdatainfo->user_index = atoi(column_values[1]);
    pdatainfo->data_version = atoi(column_values[2]);
    strncpy(pdatainfo->toxid,column_values[3],TOX_ID_STR_LEN);
    strncpy(pdatainfo->datafile_md5,column_values[4],PNR_MD5_VALUE_MAXLEN);
    strncpy(pdatainfo->datafile_curpath,column_values[5],PNR_FILEPATH_MAXLEN);
    strncpy(pdatainfo->datafile_curpath,column_values[6],PNR_FILEPATH_MAXLEN);
	return OK;
}

/**********************************************************************************
  Function:      pnr_tox_datafile_dbinsert
  Description:   数据库插入新的tox data记录操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_tox_datafile_dbinsert(int index)
{
    int8* errMsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(index < 0 || index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    //这里要检查一下，避免重复插入
    /*tox_datafile_tbl (id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile)*/
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from tox_datafile_tbl where toxid='%s';",
            g_tox_datafile[index].toxid);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_tox_datafile_dbinsert user instance exsit");
        return OK;
    }      
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into tox_datafile_tbl values(NULL,%d,%d,'%s','%s','%s','%s');",
             g_tox_datafile[index].user_index,g_tox_datafile[index].data_version,g_tox_datafile[index].toxid,
             g_tox_datafile[index].datafile_md5,g_tox_datafile[index].datafile_curpath,g_tox_datafile[index].datafile_bakpath);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_usr_instance_insert:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      pnr_tox_datafile_md5update_byid
  Description:   数据库更新data的md5值
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_tox_datafile_md5update_byid(int userindex,int data_version,char* md5)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(md5 == NULL)
    {
        return ERROR;
    }
    /*tox_datafile_tbl (id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile)*/
    snprintf(sql_cmd,SQL_CMD_LEN,"update tox_datafile_tbl set dataversion=%d,toxmd5='%s' where userindex=%d;",
        data_version,md5,userindex);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_tox_datafile_md5update_byid(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_tox_datafile_init_fromdb
 功能描述  : 从数据库中初始化用户的toxdatafile信息
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_tox_datafile_init_fromdb(void)
{
	int8* errMsg = NULL;
	char sql[SQL_CMD_LEN] = {0};
    char **dbResult; 
    int nRow = 0, nColumn = 0;;
    int i,offset;
    int temp_userindex = 0;

    memset(&g_tox_datafile,0,sizeof(g_tox_datafile));
    //获取账户信息
    /*tox_datafile_tbl (id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile)*/
	snprintf(sql, SQL_CMD_LEN, "select id,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile from tox_datafile_tbl;");
    if(sqlite3_get_table(g_db_handle, sql, &dbResult, &nRow, &nColumn, &errMsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow ; i++ )
        {           
            temp_userindex = atoi(dbResult[offset+1]);
            if(temp_userindex >= 0 && temp_userindex <= PNR_IMUSER_MAXNUM)
            {
                g_tox_datafile[temp_userindex].dbid = atoi(dbResult[offset]);
                g_tox_datafile[temp_userindex].user_index = temp_userindex;
                g_tox_datafile[temp_userindex].data_version = atoi(dbResult[offset+2]);
                strncpy(g_tox_datafile[temp_userindex].toxid,dbResult[offset+3],TOX_ID_STR_LEN);
                strncpy(g_tox_datafile[temp_userindex].datafile_md5,dbResult[offset+4],PNR_MD5_VALUE_MAXLEN);
                strncpy(g_tox_datafile[temp_userindex].datafile_curpath,dbResult[offset+5],PNR_FILEPATH_MAXLEN);
                strncpy(g_tox_datafile[temp_userindex].datafile_bakpath,dbResult[offset+6],PNR_FILEPATH_MAXLEN);
            }
            else
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad temp_userindex %d",temp_userindex);
            }
            offset += nColumn;
         }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_tox_datafile_dbdelete_bytoxid
  Description:   数据库删除data记录
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_tox_datafile_dbdelete_bytoxid(char* toxid)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(toxid == NULL)
    {
        return ERROR;
    }
    /*tox_datafile_tbl (id integer primary key autoincrement,userindex,dataversion,toxid,toxmd5,curdatafile,bakdatafile)*/
    snprintf(sql_cmd,SQL_CMD_LEN,"delete from tox_datafile_tbl where toxid='%s';",toxid);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_tox_datafile_dbdelete_bytoxid(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/*****************************************************************************
 函 数 名  : pnr_devloginkey_dbupdate
 功能描述  : 更新设备管理登陆密码
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_devloginkey_dbupdate(char* loginkey)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(loginkey == NULL)
    {
        return ERROR;
    }

	snprintf(sql_cmd,SQL_CMD_LEN,"update generconf_tbl set value='%s' where name='%s';",
        loginkey,DB_DEVLOGINEKEY_KEYWORD);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_devloginkey_dbupdate(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : pnr_devname_dbupdate
 功能描述  : 更新设备名称
 输入参数  : null
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月17日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int pnr_devname_dbupdate(char* new_name)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(new_name == NULL)
    {
        return ERROR;
    }

	snprintf(sql_cmd,SQL_CMD_LEN,"update generconf_tbl set value='%s' where name='%s';",
        new_name,DB_DEVNAME_KEYWORD);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_devname_dbupdate(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_group_dbinsert
  Description:  插入pnr group 信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_group_dbinsert(int gid,int uindex,int verify,char* utoxid,char* name,char* group_hid)
{
	int8* errMsg = NULL;
    int count = 0;
	char sql_cmd[SQL_CMD_LEN] = {0};

     if(name  == NULL || group_hid == NULL || utoxid == NULL || gid < 0 || uindex < 0 || name == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_insert:input err");
        return ERROR;
    }
    //这里要检查一下，避免重复插入
    //grouplist_tbl(id,hash,owner,ownerid,verify,manager,gname,createtime);
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from grouplist_tbl where id=%d;",gid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_group_dbinsert group(%d) exsit",gid);
        return OK;
    }      
    //grouplist_tbl(id,hash,owner,ownerid,verify,manager,gname,createtime);
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into grouplist_tbl values(%d,'%s','%s',%d,%d,'','%s',%d);",
             gid,group_hid,utoxid,uindex,verify,name,(int)time(NULL));
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_group_dbinsert:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_group_dbdelete_bygid
  Description:  根据id删除对应群信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_group_dbdelete_bygid(int gid)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM )
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_group_dbdelete_bygid:input err");
        return ERROR;
    }
    //这里区分下，是全部删除还是单个删除
    //grouplist_tbl(id,hash,owner,ownerid,verify,manager,gname,createtime);
    snprintf(sql_cmd,SQL_CMD_LEN,"delete from grouplist_tbl where id=%d;",gid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupname_dbupdate_bygid
  Description:  根据id修改对应群名称
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupname_dbupdate_bygid(int gid,char* gname)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM || gname == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupname_dbupdate_bygid:input err");
        return ERROR;
    }
    //grouplist_tbl(id,hash,owner,ownerid,verify,manager,gname,createtime);
    snprintf(sql_cmd,SQL_CMD_LEN,"update grouplist_tbl set gname='%s' where id=%d;",gname,gid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupverify_dbupdate_bygid
  Description:  根据id修改对应群审核权限
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupverify_dbupdate_bygid(int gid,int verify)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM || (verify != FALSE && verify != TRUE))
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupname_dbupdate_bygid:input err");
        return ERROR;
    }
    //grouplist_tbl(id,hash,owner,ownerid,verify,manager,gname,createtime);
    snprintf(sql_cmd,SQL_CMD_LEN,"update grouplist_tbl set verify=%d where id=%d;",verify,gid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/***********************************************************************************
  Function:      pnr_groupuser_insert
  Description:  插入pnr group user信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupuser_dbinsert(int gid,int uid,int uindex,int type,int msgid,char* utoxid,char* name,char* userkey)
{
	int8* errMsg = NULL;
    int count = 0;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(name  == NULL || userkey == NULL || utoxid == NULL || gid < 0 || uid < 0 
        || type < GROUP_USER_OWNER || type >= GROUP_USER_BUTT)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_insert:input err");
        return ERROR;
    }
    //这里要检查一下，避免重复插入
    //groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from groupuser_tbl where gid=%d and uindex=%d;",gid,uindex);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_insert group(%d) user(%d) exsit",gid,uindex);
        return OK;
    }      
    //groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey)
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into groupuser_tbl values(%d,%d,%d,%d,%d,%d,%d,'%s','%s','','','%s');",
             gid,uid,uindex,type,msgid,msgid,(int)time(NULL),utoxid,name,userkey);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_insert:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupuser_gremark_dbupdate_byid
  Description:  根据id修改对应群名称
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupuser_gremark_dbupdate_byid(int gid,int uindex,char* gname)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM || gname == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupname_dbupdate_bygid:input err");
        return ERROR;
    }
    //groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"update groupuser_tbl set gremark='%s' where gid=%d and uindex=%d;",gname,gid,uindex);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupuser_lastmsgid_dbupdate_byid
  Description:  根据id修改对应读取最新的msgid
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupuser_lastmsgid_dbupdate_byid(int gid,int uindex,int last_msgid)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM || last_msgid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_lastmsgid_dbupdate_byid:input err");
        return ERROR;
    }
    //groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"update groupuser_tbl set lastmsgid=%d where gid=%d and uindex=%d;",last_msgid,gid,uindex);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

/***********************************************************************************
  Function:      pnr_groupuser_dbdelete_byuid
  Description:  根据id删除对应群中用户
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupuser_dbdelete_byuid(int gid,int uindex)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM || uindex < 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_delbyuid:input err");
        return ERROR;
    }
    //这里区分下，是全部删除还是单个删除
    //groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey)
    if(uindex == 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"delete from groupuser_tbl where gid=%d;",gid);
    }
    else
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"delete from groupuser_tbl where gid=%d and uindex=%d;",gid,uindex);
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_dbdelete_byuid:sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupmsg_dbinsert
  Description:  插入pnr group msg信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupmsg_dbinsert(int gid,int uindex,int msgid,int type,char* sender,char* msg,char* attend,char* ext,char* ext2,char* filekey)
{
	int8* errMsg = NULL;
    int count = 0;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char* p_attend = "";
    char* p_ext = "";
    char* p_ext2 = "";
    char* p_filekey = "";
    char* p_sql = NULL;
    int sql_malloc_flag = FALSE;
    if(sender  == NULL || msg == NULL  || gid < 0 || uindex < 0 )
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupmsg_dbinsert:input err");
        return ERROR;
    }
    if(msg != NULL && strlen(msg) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_groupmsg_dbinsert:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
    }
    else
    {
        p_sql = sql_cmd;
    }
    if(attend != NULL)
    {
        p_attend = attend;
    }
    if(ext != NULL)
    {
        p_ext = ext;
    }
    if(ext2 != NULL)
    {
        p_ext2 = ext2;
    }
    if(filekey != NULL)
    {
        p_filekey = filekey;
    }
    //这里要检查一下，避免重复插入
    //groupmsg_tbl(gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey)   
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from groupmsg_tbl where gid=%d and msgid=%d;",gid,msgid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,dbget_int_result,&count,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupmsg_dbinsert group(%d) msgid(%d) exsit",gid,msgid);
        return OK;
    }      
    //groupmsg_tbl(gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey)
    if(sql_malloc_flag == TRUE)
    {
    	snprintf(p_sql,MSGSQL_ALLOC_MAXLEN,"insert into groupmsg_tbl values(%d,%d,%d,%d,%d,'%s','%s','%s','%s','%s','%s');",
             gid,msgid,uindex,(int)time(NULL),type,sender,msg,p_attend,p_ext,p_ext2,p_filekey);
    }
    else
    {
    	snprintf(p_sql,MSGSQL_CMD_LEN,"insert into groupmsg_tbl values(%d,%d,%d,%d,%d,'%s','%s','%s','%s','%s','%s');",
             gid,msgid,uindex,(int)time(NULL),type,sender,msg,p_attend,p_ext,p_ext2,p_filekey);
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupmsg_dbinsert:sql(%s)",p_sql);
    if(sqlite3_exec(g_groupdb_handle,p_sql,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",p_sql,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    if(sql_malloc_flag == TRUE)
    {
        free(p_sql);
    }   
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupmsg_dbget_lastmsgid
  Description:  获取最大的msgid值
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupmsg_dbget_lastmsgid(int gid,int* pmsgid)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    if(pmsgid == NULL  || gid < 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupmsg_dbinsert:input err");
        return ERROR;
    }
    
    //这里要检查一下，避免重复插入
    //groupmsg_tbl(gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select max(msgid) from groupmsg_tbl where gid=%d;",gid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,dbget_int_result,pmsgid,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"gid(%d) get max msgid cmd(%s) err(%s)",gid,sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }     
    
    return OK;
}

/***********************************************************************************
  Function:      pnr_groupmsg_dbdelete_bymsgid
  Description:  根据msgid删除对应消息记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupmsg_dbdelete_bymsgid(int gid,int msgid)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupuser_delbyuid:input err");
        return ERROR;
    }
    //这里区分下，是全部删除还是单个删除
    //groupmsg_tbl(gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey)
    if(msgid == 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"delete from groupmsg_tbl where gid=%d;",gid);
    }
    else
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"delete from groupmsg_tbl where gid=%d and msgid=%d;",gid,msgid);
    }
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_groupmsg_dbget
  Description:   数据库查询单条群消息记录
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_groupmsg_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    if(n_columns < 10)
    {
        return ERROR;
    }
	struct group_user_msg* pmsg = (struct group_user_msg*)obj;
    if(pmsg == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_groupmsg_dbget obj is null");
        return ERROR;
    }
    memset(pmsg,0,sizeof(struct group_user_msg));
    //"select gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey from groupmsg_tbl where gid=%d and msgid=%d;"
    pmsg->gid = atoi(column_values[0]);
    pmsg->msgid = atoi(column_values[1]);
    pmsg->from_uid= atoi(column_values[2]);
    pmsg->timestamp= atoi(column_values[3]);
    pmsg->type = atoi(column_values[4]);
    if(column_values[5] != NULL)
    {
        strncpy(pmsg->from,column_values[5],TOX_ID_STR_LEN);
    }
    if(column_values[6] != NULL)
    {
        strncpy(pmsg->msgpay,column_values[6],PNR_GROUP_USERMSG_MAXLEN);
    }
    if(column_values[7] != NULL)
    {
        strncpy(pmsg->attend,column_values[7],PNR_GROUP_EXTINFO_MAXLEN);
    }
    if(column_values[8] != NULL)
    {
        strncpy(pmsg->ext1,column_values[8],PNR_GROUP_EXTINFO_MAXLEN);
    }
    if(column_values[9] != NULL)
    {
        strncpy(pmsg->ext2,column_values[9],PNR_GROUP_EXTINFO_MAXLEN);
    } 
    if(column_values[10] != NULL)
    {
        strncpy(pmsg->file_key,column_values[10],PNR_GROUP_USERKEY_MAXLEN);
    } 
	return OK;
}
/***********************************************************************************
  Function:      pnr_groupmsg_dbget_bymsgid
  Description:  根据msgid获取对应消息记录
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupmsg_dbget_bymsgid(int gid,int msgid,struct group_user_msg* pmsg)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(gid < 0 || gid > PNR_GROUP_MAXNUM || msgid <= 0 || pmsg == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupmsg_dbget_bymsgid:input err");
        return ERROR;
    }
    //groupmsg_tbl(gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select gid,msgid,userindex,timestamp,msgtype,sender,msg,attend,ext,ext2,filekey from groupmsg_tbl where gid=%d and msgid=%d;",gid,msgid);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,pnr_groupmsg_dbget,pmsg,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_groupoper_dbget_insert
  Description:  记录群操作
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_groupoper_dbget_insert(int gid,int action,int fromid,int toid,char* gname,char* from,char* to,char* ext)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    char* pgname = "";
    char* pfrom = "";
    char* pto = "";
    char* pext = "";
    if(gid < 0 || gid > PNR_GROUP_MAXNUM )
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupoper_dbget_insert:input err");
        return ERROR;
    }
    if(gname != NULL)
    {
        pgname = gname;
    }
    if(from != NULL)
    {
        pfrom = from;
    }
    if(to != NULL)
    {
        pto = to;
    }
    if(ext != NULL)
    {
        pext = ext;
    }
    //groupoperateinfo_tbl(gid,action,timestamp,fromId,toId,gname,fromuser,touser,ext);
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into groupoperateinfo_tbl values(%d,%d,%d,%d,%d,'%s','%s','%s','%s');",
             gid,action,(int)time(NULL),fromid,toid,pgname,pfrom,pto,pext);
    if(sqlite3_exec(g_groupdb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_netconfig_dbget
  Description:   数据库查询网络相关配置参数
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_netconfig_dbget(struct pnrdev_netconn_info* pinfo)
{
    int8* errMsg = NULL;
    struct db_string_ret db_ret;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(pinfo == NULL)
    {
        return ERROR;
    }
    memset(pinfo,0,sizeof(struct pnrdev_netconn_info));
    db_ret.buf_len = IPSTR_MAX_LEN;
    db_ret.pbuf = pinfo->pub_ipstr;
	snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_PUBNET_IPSTR_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_singstr_result,&db_ret,&errMsg))
	{
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get pubnet_ip failed");
		sqlite3_free(errMsg);
		return ERROR;
	}
    snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_PUBNETMODE_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&(pinfo->pubnet_mode),&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get pubnet_mode failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_FRPMODE_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&(pinfo->frp_mode),&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get frp_mode failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_PUBNET_SSHPORT_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&(pinfo->ssh_port),&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get ssh_port failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_PUBNET_PORT_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&(pinfo->pnr_port),&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get pnr_port failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"select value from generconf_tbl where name='%s';",DB_FRPPORT_KEYWORD);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,&(pinfo->frp_port),&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get pnr_port failed");
        sqlite3_free(errMsg);
        return ERROR;
    }
	return OK;
}
/***********************************************************************************
  Function:      pnr_logcache_dbinsert
  Description:  插入操作缓存信息信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_logcache_dbinsert(int cmd,char* fromid,char* toid,char* msg,char* ext)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    char* p_ext = "";
    char* p_msg = "";
    if(fromid  == NULL || toid == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_groupmsg_dbinsert:input err");
        return ERROR;
    }
    if(msg != NULL)
    {
        p_msg = msg;
    }
    if(ext != NULL)
    {
        p_ext = ext;
    }
 
    //log_cache_tbl(timestamp,type,from_user,to_user,msg,ext)
	snprintf(sql_cmd,SQL_CMD_LEN,"insert into log_cache_tbl values(%d,%d,'%s','%s','%s','%s');",
             (int)time(NULL),cmd,fromid,toid,p_msg,p_ext);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_logcache_dbinsert:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_filelist_dbinsert
  Description:  插入pnr file 信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelist_dbinsert(int uindex,int msgid,int filetype,int srcfrom,int size,
                            char* from,char* to,char* filename,char* filepath,
                            char* md5,char* fileinfo,char* skey,char* dkey)
{
	int8* errMsg = NULL;
    char* p_fileinfo = "";
    char* p_skey = "";
    char* p_dkey = "";
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(filename  == NULL || to == NULL || filename == NULL || filepath == NULL || md5 == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbinsert:input err");
        return ERROR;
    }
    if(uindex <= 0 || uindex > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbinsert:bad");
        return ERROR;
    }
    if(skey != NULL)
    {
        p_skey = skey;
    }
    if(dkey != NULL)
    {
        p_dkey = dkey;
    }
    if(fileinfo != NULL)
    {
        p_fileinfo = fileinfo;
    }
    //filelist_tbl(userindex,timestamp,id integer primary key autoincrement,version,msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into filelist_tbl values(%d,%d,null,%d,%d,%d,%d,%d,'%s','%s','%s','%s','%s','%s','%s','%s');",
             uindex,(int)time(NULL),WS_FILELIST_VERSION,msgid,filetype,srcfrom,size,from,to,filename,filepath,md5,p_fileinfo,p_skey,p_dkey);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_filelist_dbinsert:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_msglogdb_handle[uindex],sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_filelist_dbupdate_fileinfo_bymsgid
  Description:  更新pnr file 信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelist_dbupdate_fileinfo_bymsgid(int uindex,int msgid,int srcfrom,int size,
                            char* md5,char* fileinfo,char* skey,char* dkey)
{
	int8* errMsg = NULL;
    int attach_flag = FALSE;
    char sql_tmpstr[CMD_MAXLEN] = {0};
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(uindex <= 0 || uindex > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbupdate_fileinfo_bymsgid:bad");
        return ERROR;
    }
    snprintf(sql_cmd,SQL_CMD_LEN,"update filelist_tbl set ");
    if(size > 0)
    {
        attach_flag = TRUE;
        snprintf(sql_tmpstr,CMD_MAXLEN,"size=%d",size);
        strcat(sql_cmd,sql_tmpstr);
    }
    if(md5)
    {
        if(attach_flag == TRUE)
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,",md5='%s'",md5);
        }
        else
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,"md5='%s'",md5);
            attach_flag = TRUE;
        }
        strcat(sql_cmd,sql_tmpstr);
    }
    if(fileinfo)
    {
        if(attach_flag == TRUE)
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,",fileinfo='%s'",fileinfo);
        }
        else
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,"fileinfo='%s'",fileinfo);
            attach_flag = TRUE;
        }
        strcat(sql_cmd,sql_tmpstr);
    }
    if(skey)
    {
        if(attach_flag == TRUE)
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,",skey='%s'",skey);
        }
        else
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,"skey='%s'",skey);
            attach_flag = TRUE;
        }
        strcat(sql_cmd,sql_tmpstr);
    }
    if(dkey)
    {
        if(attach_flag == TRUE)
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,",dkey='%s'",dkey);
        }
        else
        {
            snprintf(sql_tmpstr,CMD_MAXLEN,"dkey='%s'",dkey);
            attach_flag = TRUE;
        }
        strcat(sql_cmd,sql_tmpstr);
    }
    if(attach_flag == FALSE)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbupdate_fileinfo_bymsgid:bad sql_cmd(%s)",sql_cmd);
        return ERROR;
    }
    snprintf(sql_tmpstr,CMD_MAXLEN," where userindex=%d and srcfrom=%d and msgid=%d",uindex,srcfrom,msgid);
    strcat(sql_cmd,sql_tmpstr);
    //filelist_tbl(userindex,timestamp,id integer primary key autoincrement,version,msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey)
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_filelist_dbupdate_fileinfo_bymsgid:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_msglogdb_handle[uindex],sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_filelist_dbupdate_filename_bymsgid
  Description:  更新pnr file 文件名
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelist_dbupdate_filename_bymsgid(int uindex,int msgid,int srcfrom,char* filename)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};

    if(uindex <= 0 || uindex > PNR_IMUSER_MAXNUM || filename == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbupdate_filename_bymsgid:bad params");
        return ERROR;
    }
    //filelist_tbl(userindex,timestamp,id integer primary key autoincrement,version,msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"update filelist_tbl set filename='%s' where userindex=%d and srcfrom=%d and msgid=%d",filename,uindex,srcfrom,msgid);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_filelist_dbupdate_filename_bymsgid:sql(%s)",sql_cmd);
    if(sqlite3_exec(g_msglogdb_handle[uindex],sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      pnr_filelist_dbinfo_dbget
  Description:   数据库查询用户信息操作
  Calls:          
  Called By:     main
  Input:         
  Output:        none
  Return:        0:调用成功
                     1:调用失败
  Others: 
  History: 1. Date:2008-10-22
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int32 pnr_filelist_dbinfo_dbget(void* obj, int n_columns, char** column_values,char** column_names)
{
    int i =0;
    if(n_columns < 8)
    {
        return ERROR;
    }
	struct pnr_file_dbinfo_struct* p_file = (struct pnr_file_dbinfo_struct*)obj;
    if(p_file == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbinfo_dbget obj is null");
        return ERROR;
    }
    //filelist_tbl(userindex,timestamp,id integer primary key autoincrement,version,msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey)
    p_file->uid = atoi(column_values[i++]);
    p_file->timestamp = atoi(column_values[i++]);
    p_file->id = atoi(column_values[i++]);
    p_file->info_ver = atoi(column_values[i++]);
    p_file->msgid = atoi(column_values[i++]);
    p_file->filetype = atoi(column_values[i++]);
    p_file->srcfrom = atoi(column_values[i++]);
    p_file->filesize = atoi(column_values[i++]);
    if(column_values[i] != NULL)
    {
        strncpy(p_file->from,column_values[i],TOX_ID_STR_LEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->to,column_values[i],TOX_ID_STR_LEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->filename,column_values[i],PNR_FILENAME_MAXLEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->filepath,column_values[i],PNR_FILEPATH_MAXLEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->md5,column_values[i],PNR_MD5_VALUE_MAXLEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->fileinfo,column_values[i],PNR_FILEINFO_MAXLEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->srckey,column_values[i],PNR_RSA_KEY_MAXLEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(p_file->dstkey,column_values[i],PNR_RSA_KEY_MAXLEN);
    }
	return OK;
}
/***********************************************************************************
  Function:      pnr_filelist_dbinfo_getbyid
  Description:  插入pnr file 信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelist_dbinfo_getbyid(int uindex,int msgid,int srcfrom,struct pnr_file_dbinfo_struct* p_file_dbinfo)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    if(uindex <= 0 || uindex > PNR_IMUSER_MAXNUM || p_file_dbinfo == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbinsert:bad params");
        return ERROR;
    }
    memset(p_file_dbinfo,0,sizeof(struct pnr_file_dbinfo_struct));
    //filelist_tbl(userindex,timestamp,id integer primary key autoincrement,version,msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from filelist_tbl where userindex=%d and srcfrom=%d and msgid=%d",uindex,srcfrom,msgid);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_filelist_dbinfo_getbyid:sql(%s)",sql_cmd);
     if(sqlite3_exec(g_msglogdb_handle[uindex],sql_cmd,pnr_filelist_dbinfo_dbget,p_file_dbinfo,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      pnr_filelist_dbinsert
  Description:  插入pnr file 信息
  Calls:
  Called By:     main
  Input:
  Output:
  Return:
  Others:

  History:
  History: 1. Date:2015-10-08
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int pnr_filelist_dbdelete_byid(int uindex,int msgid,int srcfrom)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    if(uindex <= 0 || uindex > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_filelist_dbinsert:bad params");
        return ERROR;
    }
    //filelist_tbl(userindex,timestamp,id integer primary key autoincrement,version,msgid,filetype,srcfrom,size,fromid,toid,filename,filepath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"delete from filelist_tbl where userindex=%d and srcfrom=%d and msgid=%d",uindex,srcfrom,msgid);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"pnr_filelist_dbdelete_byid:sql(%s)",sql_cmd);
     if(sqlite3_exec(g_msglogdb_handle[uindex],sql_cmd,NULL,NULL,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}

