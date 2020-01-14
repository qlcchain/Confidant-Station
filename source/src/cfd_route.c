/*************************************************************************
 *
 *  confidant 寻址接口
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
#include <string.h>
#include <cJSON.h>
#include "common_lib.h"
#include "sql_db.h"
#include "pn_imserver.h"   
#include "tox_seg_msg.h"
#include "cfd_route.h"
#include "net_crypto.h"
#include "crc32.h"
#include "aes.h"

uint32 g_checklocal_totalnum = 0;
uint32 g_checklocal_cachematchnum = 0;
uint32 g_checklocal_getfail = 0;

uint32 g_getactiveuser_totalnum = 0;
uint32 g_getactiveuser_cachematchnum = 0;
uint32 g_getactiveuser_getfail = 0;
uint32 g_rusers_checktotalnum = 0;
uint32 g_rusers_cachematchnum = 0;
uint32 g_rusers_checkfail = 0;
uint32 g_oldusers_checktotalnum = 0;
uint32 g_oldusers_cachematchnum = 0;
uint32 g_oldusers_checkfail = 0;
uint32 g_online_msgid = 1;
//全局寻址列表
struct cfd_nodeinfo_struct g_rlist_node[CFD_RNODE_MAXNUM+1];
struct cfd_uinfo_struct g_ruser_list[CFD_URECORD_MAXNUM+1];
struct cfd_uinfo_struct* gp_ruser_cachelist[CFD_URECORD_MAXNUM+1];
struct cfd_uinfo_struct* gp_localuser[PNR_IMUSER_MAXNUM+1];
struct cfd_useractive_struct g_activeuser_list[CFD_URECORD_MAXNUM+1];
struct cfd_useractive_struct* gp_cacheactive_hashlist[CFD_URECORD_MAXNUM+1];
struct cfd_friends_record g_friendrecords[PNR_IMUSER_MAXNUM+1][PNR_IMUSER_FRIENDS_MAXNUM+1];
struct cfd_generinfo g_cfdgeninfo;
pthread_mutex_t g_activeuser_lock[CFD_URECORD_MAXNUM+1];

struct cfd_olddata_mapping g_oldusers[CFD_RNODE_MAXNUM+1];
struct cfd_olddata_mapping* gp_oldusers_cachebytoxid[CFD_RNODE_MAXNUM+1];
struct cfd_olddata_mapping* gp_localoldusers[PNR_IMUSER_MAXNUM+1];

struct cfd_userfilelist_struct g_filelists[PNR_IMUSER_MAXNUM+1];
struct cfd_node_online_msghead g_nodeonline_info;
struct cfd_node_online_msgstruct g_onlinemsg;
char g_cacheonline_data[IM_MSG_PAYLOAD_MAXLEN+1] = {0};
pthread_mutex_t g_onlinemsg_lock = PTHREAD_MUTEX_INITIALIZER;

int g_nodeonline_info_ok = FALSE;
//外部全局变量
extern sqlite3 *g_db_handle;
extern sqlite3 *g_friendsdb_handle;
extern sqlite3 *g_emaildb_handle;
extern sqlite3 *g_rnodedb_handle;
extern sqlite3 *g_groupdb_handle;
extern sqlite3 *g_msglogdb_handle[PNR_IMUSER_MAXNUM+1];
extern sqlite3 *g_msgcachedb_handle[PNR_IMUSER_MAXNUM+1];
extern int g_pnrdevtype;
extern int g_p2pnet_init_flag;
extern int g_noticepost_enable;
extern char g_dev_hwaddr[MACSTR_MAX_LEN];
extern char g_dev_nickname[PNR_USERNAME_MAXLEN+1];
extern struct im_user_struct g_daemon_tox;//节点根id，用于给用户tox连接和节点间消息同步
extern struct im_user_struct g_rnode_tox;//节点路由id，用于给用户寻址，跨节点收发消息
extern struct im_user_array_struct g_imusr_array;
extern struct group_info g_grouplist[PNR_GROUP_MAXNUM+1];
extern struct pnr_account_array_struct g_account_array;
extern struct lws_cache_msg_struct g_lws_cache_msglist[PNR_IMUSER_MAXNUM+1];
extern struct pnr_postmsgs_cache g_group_pushmsgs_cache;
extern pthread_mutex_t g_pnruser_lock[PNR_IMUSER_MAXNUM+1];
extern pthread_mutex_t g_user_friendlock[PNR_IMUSER_MAXNUM+1];
extern pthread_mutex_t g_user_msgidlock[PNR_IMUSER_MAXNUM+1];
extern pthread_mutex_t lws_cache_msglock[PNR_IMUSER_MAXNUM+1];
/**********************************************************************************
  Function:      get_uindexbyuid
  Description:  根据uid获取该用户得id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int get_uindexbyuid(char* p_uid)
{
    int i =0;
    if(p_uid == NULL)
    {
        return -1;
    }
    for(i=0;i<=PNR_GROUP_USER_MAXNUM;i++)
    {
        if(gp_localuser[i] != NULL)
        {
            if(strcmp(p_uid,gp_localuser[i]->uidstr) == OK)
            {
                return gp_localuser[i]->index;
            }
        }
    }
    return -1;
}
/**********************************************************************************
  Function:      cfd_uinfolist_getidleid
  Description:  根据uid获取该用户得id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfolist_getidleid(void)
{
    int i =0;
    for(i=1;i<=CFD_URECORD_MAXNUM;i++)
    {
        if(g_ruser_list[i].id == 0)
        {
            return i;
        }
    }
    return -1;
}
/**********************************************************************************
  Function:      cfd_rnodelist_getidleid
  Description:  获取当前空闲node id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_getidleid(void)
{
    int i =0;
    for(i=2;i<=CFD_RNODE_MAXNUM;i++)
    {
        if(g_rlist_node[i].id == 0)
        {
            return i;
        }
    }
    return -1;
}
/**********************************************************************************
  Function:      cfd_rnodelist_getid_bydevid
  Description:  根据toxid获取
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_getid_bydevid(int node_flag,char* devid)
{
    int i =0;
    if(devid == NULL || strlen(devid) < TOX_ID_STR_LEN)
    {
        return -1;
    }
    if(node_flag == CFD_NODE_TOXID_NID)
    {
        for(i=CFD_RNODE_DEFAULT_RID;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(strcmp(devid,g_rlist_node[i].nodeid) == OK)
            {
                return i;
            }
        }
    }
    else
    {
        for(i=CFD_RNODE_DEFAULT_RID;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(strcmp(devid,g_rlist_node[i].routeid) == OK)
            {
                return i;
            }
        }
    }
    return -1;
}

/**********************************************************************************
  Function:      cfd_friendidstr_dbget_func
  Description:   数据库查询用户id回掉
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
int32 cfd_friendidstr_dbget_func(void* obj, int n_columns, char** column_values,char** column_names)
{
    struct cfd_friends_record *puser = NULL;
    if(n_columns < 2 || obj == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_friendidstr_dbget_func get n_columns(%d)",n_columns);
        return ERROR;
    }
	puser = (struct cfd_friends_record*)obj;
    if(column_values[0] != NULL)
    {
        strncpy(puser->remark,column_values[0],PNR_USERNAME_MAXLEN);
    }
    if(column_values[1] != NULL)
    {
         strncpy(puser->fidstr,column_values[1],PNR_USERNAME_MAXLEN);
    }  
	return OK;
}
/**********************************************************************************
  Function:      cfd_friendidstr_dbget_bytoxid
  Description:  根据用户friend toxid查询friends_tbl的friendname,userkey，根据旧版数据生成新用户得时候调用
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_friendidstr_dbget_bytoxid(char* p_friend_idstr,char* p_fname,char* p_uidstr)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_friends_record record;

    if(p_friend_idstr == NULL || p_fname == NULL || p_uidstr == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstr:bad input");
        return ERROR;
    }
    memset(&record,0,sizeof(record));
    //friends_tbl(id,timestamp,userid,friendid,friendname,userkey,oneway,remarks);
    snprintf(sql_cmd,SQL_CMD_LEN,"select friendname,userkey from friends_tbl where friendid='%s' limit 1",p_friend_idstr);
    if(sqlite3_exec(g_friendsdb_handle,sql_cmd,cfd_friendidstr_dbget_func,&record,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_friendidstr_dbget_bytoxid failed(%s)",errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    if(strlen(record.remark) > 0)
    {
        strcpy(p_fname,record.remark);
    }
    if(strlen(record.fidstr) > 0)
    {
        strcpy(p_uidstr,record.fidstr);
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnodelist_string_to_array
  Description:  rnodelist 字符串解析为数组
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_string_to_array(char* nodestring,int* p_rnode_array,int* rnode_num)
{
    char* p_head = NULL;
    char* p_tail = NULL;
    char* p_end = NULL;
    int i = 0;
    int tmplen = 0;

    if(nodestring == NULL || p_rnode_array == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodelist_string_to_array:bad input");
        return ERROR;
    }
    p_head = nodestring;
    p_end = p_head+strlen(nodestring);
    while(p_head != NULL && p_head < p_end)
    {
        p_tail = strchr(p_head,EM_CACHE_SEPARATION_CHAR);
        if(p_tail)
        {
            tmplen = p_tail - p_head;
            if(tmplen <= 0)
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"repeat separation(%s)",p_head);
            }
            else
            {
                if(i < CFD_ACTIVERID_MAXNUM)
                {
                    *(p_rnode_array+i) = atoi(p_head);
                    if(*(p_rnode_array+i) <= 0)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_INFO,"bad rnode_id(%s)",p_head);
                    }
                    i++;
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"users num over(%d)",i);
                    return ERROR;
                }
            }
            p_tail++;
            p_head = p_tail;
        }
        else
        {
            tmplen = strlen(p_head);
            if(tmplen > 0)
            {
                *(p_rnode_array+i) = atoi(p_head);
                if(*(p_rnode_array+i) <= 0)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"bad rnode_id(%s)",p_head);
                }
                i++;
            }
            break;
        }
    }
    *rnode_num = i;
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnodelist_array_to_string
  Description:  rnodelist 数组解析为字符串
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_array_to_string(int rnode_num,int* p_rnode_array,char* nodestring)
{
    int i = 0;
    char tmp_numstrin[10] = {0};

    if(nodestring == NULL || p_rnode_array == NULL || rnode_num <= 0 || rnode_num > CFD_ACTIVERID_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodelist_array_to_string:bad input");
        return ERROR;
    }
    memset(nodestring,0,PNR_USERNAME_MAXLEN);
    for(i = 0;i< rnode_num;i++)
    {
        if(i > 0)
        {
            strcat(nodestring,EMLIST_SEPARATION_STRING);
        }
        memset(tmp_numstrin,0,10);
        snprintf(tmp_numstrin,10,"%d",*(p_rnode_array+i));
        strcat(nodestring,tmp_numstrin);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnodelist_init
  Description:  rnode list 初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_init(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i;
    int offset=0;
    int id = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    memset(&g_rlist_node,0,sizeof(struct cfd_nodeinfo_struct)*CFD_RNODE_MAXNUM);
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from rnode_list_tab;");
    if(sqlite3_get_table(g_rnodedb_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow && i < CFD_RNODE_MAXNUM; i++ )
        {               
            id = atoi(dbResult[offset]);
            g_rlist_node[id].id = id;
            g_rlist_node[id].type = atoi(dbResult[offset+1]);
            g_rlist_node[id].weight = atoi(dbResult[offset+2]);
            if(dbResult[offset+3])
            {
                strncpy(g_rlist_node[id].mac,dbResult[offset+3],MACSTR_MAX_LEN);
            }
            if(dbResult[offset+4])
            {
                strncpy(g_rlist_node[id].nodeid,dbResult[offset+4],TOX_ID_STR_LEN);
            }
            if(dbResult[offset+5])
            {
                strncpy(g_rlist_node[id].routeid,dbResult[offset+5],TOX_ID_STR_LEN);
            }
            if(dbResult[offset+6])
            {
                strncpy(g_rlist_node[id].rname,dbResult[offset+6],PNR_USERNAME_MAXLEN);
            }
            g_cfdgeninfo.rnode_num++;
            offset += nColumn;
        }
        sqlite3_free_table(dbResult);
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnodedbid_dbget_bynodeid
  Description:  根据nodeid查询rnode_list_tab的db_id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodedbid_dbget_bynodeid(char* p_nodeid,int* db_id)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_nodeid == NULL || db_id == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodedbid_dbget_bynodeid:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from rnode_list_tab where nodeid='%s';",p_nodeid);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,db_id,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstrfailed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnodedbid_dbget_bymac
  Description:  根据nodeid查询rnode_list_tab的db_id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodedbid_dbget_bymac(char* pmac)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    int rid = -1;
    if(pmac == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodedbid_dbget_bymac:bad input");
        return -1;
    }
    //先检查当前用户记录是否已经存在
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from rnode_list_tab where mac='%s';",pmac);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&rid,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstrfailed");
        sqlite3_free(errmsg);
        return -1;
    }
    return rid;
}

/**********************************************************************************
  Function:      cfd_rnodelist_dbinsert
  Description:  插入新的节点信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_dbinsert(struct cfd_nodeinfo_struct *pnode)
{
    char *errmsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(pnode == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodelist_dbinsert:bad input");
        return ERROR;
    }
    //先检查当前节点记录是否已经存在
    if(strlen(pnode->nodeid) >= TOX_ID_STR_LEN)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from rnode_list_tab where nodeid='%s';",pnode->nodeid);
        if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&count,&errmsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
            sqlite3_free(errmsg);
            return ERROR;
        }
        if(count > 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnodelist_dbinsert rnode mac(%s) exsit",pnode->nodeid);
            return ERROR;
        }     
    }
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_list_tab values(NULL,%d,%d,'%s','%s','%s','%s','%s');",
        pnode->type,pnode->weight,pnode->mac,pnode->nodeid,pnode->routeid,pnode->rname,pnode->info);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnodelist_dbinsert(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnode_dbupdate_byid
  Description:  rnode list 更新节点
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_dbupdate_byid(struct cfd_nodeinfo_struct* pnode)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(pnode == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_dbupdate_byid input error");
        return ERROR;
    }
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_list_tab set type=%d,weight=%d,mac='%s',nodeid='%s',routeid='%s',rname='%s' where id=%d",
        pnode->type,pnode->weight,pnode->mac,pnode->nodeid,pnode->routeid,pnode->rname,pnode->id);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_dbupdate_byid(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnode_dbdelte_byid
  Description:  rnode list 更新节点
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_dbdelte_byid(int rid)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(rid <= CFD_RNODE_DEFAULT_RID || rid > CFD_RNODE_MAXNUM)
    {
        return ERROR;
    }
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"delete from rnode_list_tab where id=%d",rid);    
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_dbdelte_byid(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnodelist_dbinit
  Description:  rnode list 从userdev_mapping_tbl创建初始rnode list
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_dbinit(void)
{
    char **dbResult; 
    char *errmsg = NULL;
    int nRow, nColumn,i;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_nodeinfo_struct tmpnode;

    //因为这里节点tox实例还没有起来，所以这里只是占一个记录位，等之后再更新
    //rnode_list_tab(id integer primary key autoincrement,type,weight,mac,nodeid,routeid,rname,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_list_tab values(NULL,%d,%d,'','','','','');",g_pnrdevtype,CFD_RNODE_SELF_WEIGHT);    
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnodelist_dbinit(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    //提取旧的userdev_mapping_tbl表中数据    
    snprintf(sql_cmd,SQL_CMD_LEN,"select DISTINCT devid,devname from userdev_mapping_tbl;");
    if(sqlite3_get_table(g_db_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow && i < CFD_RNODE_MAXNUM; i++ )
        {               
            memset(&tmpnode,0,sizeof(tmpnode));
            if(dbResult[offset])
            {
                strncpy(tmpnode.nodeid,dbResult[offset],TOX_ID_STR_LEN);
            }
            if(dbResult[offset+1])
            {
                strncpy(tmpnode.rname,dbResult[offset+1],PNR_USERNAME_MAXLEN);
            }
            offset += nColumn;
            if(cfd_rnodelist_dbinsert(&tmpnode) != OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodelist_dbinsert failed");
            }
        }
        sqlite3_free_table(dbResult);
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnodelist_addnewnode
  Description:  rnode list 从userdev_mapping_tbl创建初始rnode list
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodelist_addnewnode(int uid,char* p_nodeid)
{
    if(uid <= 0 || uid > CFD_RNODE_MAXNUM|| p_nodeid == NULL)
    {
        return ERROR;
    }
    memset(&g_rlist_node[uid],0,sizeof(struct cfd_nodeinfo_struct));
    g_rlist_node[uid].id = uid;
    strncpy(g_rlist_node[uid].nodeid,p_nodeid,TOX_ID_STR_LEN);
    if(cfd_rnodelist_dbinsert(&g_rlist_node[uid]) != OK)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnodelist_addnewnode:cfd_rnodelist_dbinsert failed");
        memset(&g_rlist_node[uid],0,sizeof(struct cfd_nodeinfo_struct));
        return ERROR;
    }
    if(uid > CFD_RNODE_DEFAULT_RID)
    {
        g_rlist_node[uid].node_fid = check_and_add_friends(g_daemon_tox.ptox_handle,g_rlist_node[uid].nodeid,g_daemon_tox.userinfo_fullurl);
        if(g_rlist_node[uid].node_fid < 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add friend(%s) failed",g_rlist_node[uid].nodeid);
            g_rlist_node[uid].node_cstatus = CFD_RID_NODE_CSTATUS_CONNETERR;
        }
        else
        {
            DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add friend(%s) OK",g_rlist_node[uid].nodeid);
            g_rlist_node[uid].node_cstatus = CFD_RID_NODE_CSTATUS_CONNETTING;
        }
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_userlist_init
  Description:  user list 初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_userlist_init(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i,id = 0;
    int offset=0;
    uint16 hashid=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_uinfo_struct* puser = NULL;

    //初始化
    memset(&g_ruser_list,0,sizeof(struct cfd_uinfo_struct)*(CFD_URECORD_MAXNUM+1));    
    for(i = 0 ; i<= PNR_IMUSER_MAXNUM;i++)
    {
        gp_localuser[i] = NULL;
    }
    for(i=0;i<=CFD_URECORD_MAXNUM;i++)
    {
        gp_ruser_cachelist[i] = NULL;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from rnode_uinfo_tab;");
    if(sqlite3_get_table(g_rnodedb_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow && i < CFD_URECORD_MAXNUM; i++ )
        {               
            id = atoi(dbResult[offset]);
            puser = &g_ruser_list[id];
            puser->id = id;
            puser->local = atoi(dbResult[offset+1]);
            puser->index = atoi(dbResult[offset+2]);
            puser->uinfo_seq = atoi(dbResult[offset+3]);
            puser->friend_seq = atoi(dbResult[offset+4]);
            puser->friend_num = atoi(dbResult[offset+5]);
            puser->createtime = atoi(dbResult[offset+6]);
            puser->version = atoi(dbResult[offset+7]);
            puser->type = atoi(dbResult[offset+8]);
            puser->capacity = atoi(dbResult[offset+9]);
            if(dbResult[offset+10])
            {
                strncpy(puser->uidstr,dbResult[offset+10],CFD_USER_PUBKEYLEN);
            }
            if(dbResult[offset+11])
            {
                strncpy(puser->uname,dbResult[offset+11],PNR_USERNAME_MAXLEN);
            }
            if(dbResult[offset+12])
            {
                strncpy(puser->mailinfo,dbResult[offset+12],EMAIL_USERS_CACHE_MAXLEN);
            }
            if(dbResult[offset+13])
            {
                strncpy(puser->avatar,dbResult[offset+13],PNR_FILENAME_MAXLEN);
            }
            if(dbResult[offset+14])
            {
                strncpy(puser->md5,dbResult[offset+14],PNR_MD5_VALUE_MAXLEN);
            }
            if(dbResult[offset+15])
            {
                strncpy(puser->info,dbResult[offset+15],PNR_ATTACH_INFO_MAXLEN);
            }
            if(puser->local == TRUE && (puser->index > 0 && puser->index <= PNR_IMUSER_MAXNUM))
            {
                g_cfdgeninfo.local_user++;
                if(gp_localuser[puser->index] == NULL)
                {
                    gp_localuser[puser->index] = puser;
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_userlist_init: index(%d) repeat",puser->index);
                }
            }
            memcpy(&hashid,g_ruser_list[i].uidstr,sizeof(uint16));
            hashid = (hashid & CFD_URECORD_MAXNUM);
            if(gp_ruser_cachelist[hashid] == NULL)
            {
                gp_ruser_cachelist[hashid] = &g_ruser_list[id];
            }
            g_cfdgeninfo.total_user++;
            offset += nColumn;
        }
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uinfodbid_dbget_byidstr
  Description:  根据用户idstring查询rnode_uinfo_tab的db_id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfodbid_dbget_byidstr(char* p_idstr,int* db_id)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_idstr == NULL || db_id == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstr:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from rnode_uinfo_tab where idstring='%s';",p_idstr);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,db_id,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstrfailed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uinfolistgetdbid_byuidstr
  Description:  根据uidstr查询对应数据id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfolistgetdbid_byuidstr(char* p_uidstr,int* p_uid)
{
    uint16 hashid = 0;
    int uid = -1;
    if(p_uidstr == NULL)
    {
        return ERROR;
    }
    g_rusers_checktotalnum++;
    memcpy(&hashid,p_uidstr,sizeof(uint16));
    hashid = (hashid & CFD_URECORD_MAXNUM);
    if(gp_ruser_cachelist[hashid] != NULL)
    {
        if(strcmp(gp_ruser_cachelist[hashid]->uidstr,p_uidstr) == OK)
        {
            g_rusers_cachematchnum++;
            *p_uid = gp_ruser_cachelist[hashid]->id;
            return OK;
        }
    }
    cfd_uinfodbid_dbget_byidstr(p_uidstr,&uid);
    if(uid < 0)
    {
        g_rusers_checkfail++;
        return ERROR;
    }
    *p_uid = uid;   
    return OK;
}

/**********************************************************************************
  Function:      cfd_uinfodbindex_dbget_byidstr
  Description:  根据用户idstring查询rnode_uinfo_tab的index
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfodbindex_dbget_byidstr(char* p_idstr,int* db_id)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_idstr == NULL || db_id == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstr:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select uindex from rnode_uinfo_tab where idstring='%s';",p_idstr);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,db_id,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstrfailed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"idstr(%s) get index(%d)",p_idstr,*db_id);
    return OK;
}
/**********************************************************************************
  Function:      cfd_uinfolistgetuindex_byuidstr
  Description:  根据uidstr查询对应用户index
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfolistgetindex_byuidstr(char* p_uidstr)
{
    uint16 hashid = 0;
    int uid = 0;
    if(p_uidstr == NULL)
    {
        return -1;
    }
    g_rusers_checktotalnum++;
    memcpy(&hashid,p_uidstr,sizeof(uint16));
    hashid = (hashid & CFD_URECORD_MAXNUM);
    if(gp_ruser_cachelist[hashid] != NULL)
    {
        if(strcmp(gp_ruser_cachelist[hashid]->uidstr,p_uidstr) == OK)
        {
            g_rusers_cachematchnum++;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"get uid(%d) index(%d) addr(%p)",gp_ruser_cachelist[hashid]->id,gp_ruser_cachelist[hashid]->index,gp_ruser_cachelist[hashid]);
            return gp_ruser_cachelist[hashid]->index;
        }
    }
    cfd_uinfodbindex_dbget_byidstr(p_uidstr,&uid);
    if(uid < 0)
    {
        g_rusers_checkfail++;
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get failed");
        return -1;
    }
    return uid;
}
/**********************************************************************************
  Function:      cfd_uinfoseq_dbget_byindex
  Description:  根据用户index查询rnode_uinfo_tab的db_id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfoseq_dbget_byindex(int index,int type,int* p_seq)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_seq == NULL || index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfoseq_dbget_byindex:bad input");
        return ERROR;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    switch(type)
    {
        case CFD_CHANGELOG_TYPE_USERINFO:
            snprintf(sql_cmd,SQL_CMD_LEN,"select uinfoseq from rnode_uinfo_tab where uindex=%d;",index);
            break;
        case CFD_CHANGELOG_TYPE_USERFRIENDS:
            snprintf(sql_cmd,SQL_CMD_LEN,"select friendseq from rnode_uinfo_tab where uindex=%d;",index);
            break;
        case CFD_CHANGELOG_TYPE_GROUPINFO:
            snprintf(sql_cmd,SQL_CMD_LEN,"select uinfoseq from rnode_uinfo_tab where uindex=%d;",index);
            break;
        default:
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad type(%d)",type);
            return ERROR;
    }
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,p_seq,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfoseq_dbget_byindex failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uinfoseq_dbupdate_byindex
  Description:  根据用户index更新rnode_uinfo_tab的seq
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfoseq_dbupdate_byindex(int index,int type,int seq)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfoseq_dbget_byindex:bad input");
        return ERROR;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    switch(type)
    {
        case CFD_CHANGELOG_TYPE_USERINFO:
            snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set uinfoseq=%d where uindex=%d;",seq,index);
            break;
        case CFD_CHANGELOG_TYPE_USERFRIENDS:
            snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set friendseq=%d where uindex=%d;",seq,index);
            break;
        case CFD_CHANGELOG_TYPE_GROUPINFO:
            snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set uinfoseq=%d where uindex=%d;",seq,index);
            break;
        default:
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad type(%d)",type);
            return ERROR;
    }
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfoseq_dbupdate_byindex failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_uinfomailinfo_dbupdate_byindex
  Description:  根据用户index更新rnode_uinfo_tab的mailinfo
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfomailinfo_dbupdate_byuid(int uid,int uinfoseq,char* mailinfo)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(uid <= 0 || mailinfo == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfomailinfo_dbupdate_byuid:bad input");
        return ERROR;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set uinfoseq=%d,mailinfo='%s' where id=%d;",uinfoseq,mailinfo,uid);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uinfomailinfo_dbupdate_byuid(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfomailinfo_dbupdate_byuid failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_userinfo_dbupdate_avatar
  Description:  根据用户index更新rnode_uinfo_tab的头像相关信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_userinfo_dbupdate_avatar(int index,char* avatr,char* md5)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    int uid = 0;

    if(index <= 0 || avatr == NULL || md5 == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userinfo_dbupdate_avatar:bad input");
        return ERROR;
    }
    cfd_uinfodbid_dbget_byindex(index,&uid);
    if(uid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userinfo_dbupdate_avatar:get uid error");
        return ERROR;
    }
    if(strcmp(g_ruser_list[uid].avatar,avatr) != OK || strcmp(g_ruser_list[uid].md5,md5) != OK)
    {
        g_ruser_list[uid].uinfo_seq ++;
        memset(g_ruser_list[uid].avatar,0,PNR_FILENAME_MAXLEN);
        strcpy(g_ruser_list[uid].avatar,avatr);
        memset(g_ruser_list[uid].md5,0,PNR_MD5_VALUE_MAXLEN);
        strcpy(g_ruser_list[uid].md5,md5);
         //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
        snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set uinfoseq=%d,avatar='%s',atamd5='%s' where id=%d;",
            g_ruser_list[uid].uinfo_seq,g_ruser_list[uid].avatar,g_ruser_list[uid].md5,uid);
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_userinfo_dbupdate_avatar(%s)",sql_cmd);
        if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userinfo_dbupdate_avatar failed");
            sqlite3_free(errmsg);
            return ERROR;
        }
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uinfo_dbupdate_byuid
  Description:  根据用户id更新rnode_uinfo_tab的数据
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfo_dbupdate_byuid(struct cfd_uinfo_struct* puser)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(puser == NULL || puser->id <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfo_dbupdate_byuid:bad input");
        return ERROR;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set local=%d,uindex=%d,uinfoseq=%d,friendseq=%d,friendnum=%d,"
        "type=%d,capacity=%d,idstring='%s',uname='%s',mailinfo='%s',avatar='%s',atamd5='%s' where id=%d;",
        puser->local,puser->index,puser->uinfo_seq,puser->friend_seq,puser->friend_num,
        puser->type,puser->capacity,puser->uidstr,puser->uname,puser->mailinfo,puser->avatar,puser->md5,puser->id);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uinfo_dbupdate_byuid(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfoseq_dbupdate_byindex failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_uinfouname_dbupdate_byindex
  Description:  根据用户index更新rnode_uinfo_tab的uname
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfouname_dbupdate_byindex(int uid,int uinfoseq,char* uname)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(uid <= 0 || uname== NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfouname_dbupdate_byindex:bad input");
        return ERROR;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uinfo_tab set uinfoseq=%d,uname='%s' where id=%d;",uinfoseq,uname,uid);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfomailinfo_dbupdate_byuid failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_uinfodbid_dbget_byindex
  Description:  根据用户index查询rnode_uinfo_tab的db_id
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfodbid_dbget_byindex(int uindex,int* db_id)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(db_id == NULL || uindex <=0 || uindex > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byindex:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from rnode_uinfo_tab where uindex=%d;",uindex);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,db_id,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfodbid_dbget_byidstrfailed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uinfonode_addnew
  Description:  插入新的用户信息节点
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfonode_addnew(int id,int index,int local,int type,int capacity,
        char* uidstr,char* pname,char* pmailinfo,char* pavatar,char* pmd5)
{
    uint16 hashid = 0;
    if(id <= 0 || id > CFD_URECORD_MAXNUM || uidstr == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_addnew:bad input");
        return ERROR;
    }
    if(g_ruser_list[id].id != 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfonode_addnew:uid(%d) is not null",id);
        return ERROR;
    }
    memset(&g_ruser_list[id],0,sizeof(struct cfd_uinfo_struct));
    g_ruser_list[id].id = id;
    g_ruser_list[id].index = index;
    g_ruser_list[id].local = local;
    g_ruser_list[id].createtime = (int)time(NULL);
    g_ruser_list[id].version = DEFAULT_UINFO_VERSION;
    g_ruser_list[id].uinfo_seq = DEFAULT_UINFO_VERSION;
    g_ruser_list[id].friend_seq = DEFAULT_UINFO_VERSION;
    g_ruser_list[id].type = type;
    g_ruser_list[id].capacity = capacity;
    strncpy(g_ruser_list[id].uidstr,uidstr,CFD_USER_PUBKEYLEN);
    if(pname != NULL)
    {
        strncpy(g_ruser_list[id].uname,pname,PNR_USERNAME_MAXLEN);
    }
    if(pmailinfo != NULL)
    {
        strncpy(g_ruser_list[id].mailinfo,pmailinfo,EMAIL_USERS_CACHE_MAXLEN);
    }
    if(pavatar != NULL)
    {
        strncpy(g_ruser_list[id].avatar,pavatar,PNR_FILENAME_MAXLEN);
    }
    if(pmd5 != NULL)
    {
        strncpy(g_ruser_list[id].md5,pmd5,PNR_MD5_VALUE_MAXLEN);
    }
    cfd_rnode_userinfo_dbinsert(&g_ruser_list[id]);
    memcpy(&hashid,uidstr,sizeof(uint16));
    hashid = (hashid & CFD_URECORD_MAXNUM);
    if(gp_ruser_cachelist[hashid] == NULL)
    {
        gp_ruser_cachelist[hashid] = &g_ruser_list[id];
    }
    if(index > 0 && index <= PNR_IMUSER_MAXNUM && local == TRUE)
    {
        if(gp_localuser[index] == NULL)
        {
            gp_localuser[index] = &g_ruser_list[id];
        }
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_uinfouidstr_dbget_byuindex
  Description:  根据用户uindex查询rnode_uinfo_tab的uidstr
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uinfouidstr_dbget_byuindex(int uindex,char* p_idstr)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct db_string_ret db_ret;

    if(p_idstr == NULL || uindex <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfouidstr_dbget_byuindex:bad input");
        return ERROR;
    }
    db_ret.buf_len = CFD_USER_PUBKEYLEN;
    db_ret.pbuf = p_idstr;
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select idstring from rnode_uinfo_tab where uindex=%d;",uindex);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_singstr_result,&db_ret,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfouidstr_dbget_byuindex");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnode_userinfo_dbinsert
  Description:  插入新的用户信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_userinfo_dbinsert(struct cfd_uinfo_struct *puser)
{
    char *errmsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    if(puser == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_userinfo_dbinsert:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from rnode_uinfo_tab where idstring='%s';",puser->uidstr);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&count,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_userinfo_dbinsert user(%s) exsit",puser->uidstr);
        return ERROR;
    }     
    if(puser->id > 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_uinfo_tab values(%d,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s','%s','%s');",
            puser->id,puser->local,puser->index,puser->uinfo_seq,puser->friend_seq,puser->friend_num,(int)time(NULL),puser->version,puser->type,puser->capacity,
            puser->uidstr,puser->uname,puser->mailinfo,puser->avatar,puser->md5,puser->info); 
    }
    else
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_uinfo_tab values(NULL,%d,%d,%d,%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s','%s','%s');",
            puser->local,puser->index,puser->uinfo_seq,puser->friend_seq,puser->friend_num,(int)time(NULL),puser->version,puser->type,puser->capacity,
            puser->uidstr,puser->uname,puser->mailinfo,puser->avatar,puser->md5,puser->info); 
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_userinfo_dbinsert(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      cfd_rnode_userinfo_dbinit
  Description:  新版的uinfo_tbl数据初始化
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
int cfd_rnode_userinfo_dbinit(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i,uid,rnodeid;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_uinfo_struct user;
    struct cfd_olddata_mapping tmp_olddata;    
    struct pnr_userinfo_struct srcuser;
    //提取旧的user_account_tbl表中数据,这里获取得都是本地用户    
    //user_account_tbl(id integer primary key autoincrement,lastactive,type,active,identifycode,mnemonic,usersn,userindex,nickname,loginkey,toxid,info,extinfo,pubkey, createtime, capacity)
    snprintf(sql_cmd,SQL_CMD_LEN,"select type,userindex,createtime,capacity,nickname,toxid,pubkey from user_account_tbl where active=1;");
    if(sqlite3_get_table(g_db_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for(i = 0; i < nRow ; i++)
        {               
            memset(&user,0,sizeof(user));
            memset(&srcuser,0,sizeof(srcuser));
            user.type = atoi(dbResult[offset]);
            user.index = atoi(dbResult[offset+1]);
            user.local = TRUE;
            user.createtime = atoi(dbResult[offset+2]);
            user.capacity = atoi(dbResult[offset+3]);
            if(dbResult[offset+4])
            {
                strncpy(user.uname,dbResult[offset+4],PNR_USERNAME_MAXLEN);
            }
            if(dbResult[offset+5])
            {
                strncpy(srcuser.userid,dbResult[offset+5],TOX_ID_STR_LEN);
            }
            if(dbResult[offset+6])
            {
                strncpy(user.uidstr,dbResult[offset+6],CFD_USER_PUBKEYLEN);
            }
            user.version = DEFAULT_UINFO_VERSION;
            user.uinfo_seq = DEFAULT_UINFO_VERSION;
            user.friend_seq = DEFAULT_UINFO_VERSION;
            pnr_userinfo_dbget_byuserid(&srcuser);
            strcpy(user.avatar,srcuser.avatar);
            strcpy(user.md5,srcuser.md5);
            cfg_getmails_byuindex(user.index,user.mailinfo);
            if(cfd_rnode_userinfo_dbinsert(&user) != OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_userinfo_dbinsert failed");
            }  
            else
            {
                //插入默认active用户记录
                cfd_uinfodbid_dbget_byidstr(user.uidstr,&uid);
                cfd_uactive_addnew(uid,user.index,CFD_RNODE_DEFAULT_RID,user.uidstr);
                //插入默认旧数据表记录
                memset(&tmp_olddata,0,sizeof(tmp_olddata));
                tmp_olddata.index = user.index;
                tmp_olddata.nodeid = CFD_RNODE_DEFAULT_RID;
                strcpy(tmp_olddata.idstr,user.uidstr);
                strcpy(tmp_olddata.toxid,srcuser.userid);
                cfd_oldusermapping_dbinsert(&tmp_olddata);
            }
            offset += nColumn;
        }
        sqlite3_free_table(dbResult);
    }
    //获取非本节点上得用户信息
    snprintf(sql_cmd,SQL_CMD_LEN,"select usrid,devid from userdev_mapping_tbl where userindex=0;");
    if(sqlite3_get_table(g_db_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for(i = 0; i < nRow ; i++)
        {               
            memset(&tmp_olddata,0,sizeof(tmp_olddata));
            if(dbResult[offset])
            {
                strncpy(tmp_olddata.toxid,dbResult[offset],TOX_ID_STR_LEN);
            }
            if(dbResult[offset+1])
            {
                strncpy(tmp_olddata.devid,dbResult[offset+1],TOX_ID_STR_LEN);
            }
            memset(&user,0,sizeof(user));
            //根据toxid获取uidstr
            cfd_friendidstr_dbget_bytoxid(tmp_olddata.toxid,user.uname,user.uidstr);
            if(strlen(user.uidstr) > 0)
            {
                cfd_uinfodbid_dbget_byidstr(user.uidstr,&user.id);
                //如果当前用户不在，表示是一个新用户
                if(user.id <= 0)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"###add new nolocal user(%s)",user.uidstr);
                    user.local = FALSE;
                    user.version = DEFAULT_UINFO_VERSION;
                    user.uinfo_seq = DEFAULT_UINFO_VERSION;
                    user.friend_seq = DEFAULT_UINFO_VERSION;
                    if(cfd_rnode_userinfo_dbinsert(&user) != OK)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_userinfo_dbinsert failed");
                    }  
                    else
                    {
                        //插入默认active用户记录
                        cfd_uinfodbid_dbget_byidstr(user.uidstr,&uid);
                        cfd_rnodedbid_dbget_bynodeid(tmp_olddata.devid,&rnodeid);
                        cfd_uactive_addnew(uid,0,rnodeid,user.uidstr);
                    }
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"###user(%s) exsit",user.uidstr);
                }
                //插入默认旧数据表记录
                tmp_olddata.index = 0;
                tmp_olddata.nodeid = CFD_RNODE_DEFAULT_RID;
                strcpy(tmp_olddata.idstr,user.uidstr);
                cfd_oldusermapping_dbinsert(&tmp_olddata);
            }
            offset += nColumn;
        }
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uactive_lastrid_dbget_byuid
  Description:  根据用户uid查询rnode_uactive_tab的lastrid
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_lastrid_dbget_byuid(int uid,int* lastrid)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(lastrid == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_lastrid_dbget_byuid:bad input");
        return ERROR;
    }
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    snprintf(sql_cmd,SQL_CMD_LEN,"select activenode from rnode_uactive_tab where id=%d;",uid);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,lastrid,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_lastrid_dbget_byuid failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uactive_lastrid_dbget_byuidstr
  Description:  根据用户uidstr查询rnode_uactive_tab的lastrid
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_lastrid_dbget_byuidstr(char* pidstr,int* lastrid)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(lastrid == NULL||pidstr == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_lastrid_dbget_byuid:bad input");
        return ERROR;
    }
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    snprintf(sql_cmd,SQL_CMD_LEN,"select activenode from rnode_uactive_tab where idstring='%s';",pidstr);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,lastrid,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_lastrid_dbget_byuidstr failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uactive_newuser_dbinsert
  Description:  插入新的用户活跃信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_newuser_dbinsert(struct cfd_useractive_struct *puser)
{
    char *errmsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(puser == NULL || puser->id <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_newuser_dbinsert:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from rnode_uactive_tab where id=%d;",puser->id);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&count,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uactive_newuser_dbinsert user(%s) exsit",puser->uidstr);
        return ERROR;
    }     
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_uactive_tab values(%d,%d,%d,%d,%d,%d,'%s','%s');",
        puser->id,(int)time(NULL),puser->uindex,puser->status,puser->active_rid,puser->rid_num,puser->uidstr,puser->rid_liststr);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uactive_newuser_dbinsert(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_activelist_init
  Description:  user active list 初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_activelist_init(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i,id =0;
    uint16 hashid = 0;
    int offset=0,rid_num;
    char sql_cmd[SQL_CMD_LEN] = {0};

    memset(&g_activeuser_list,0,sizeof(struct cfd_useractive_struct)*(CFD_RNODE_MAXNUM+1));
    for(i=0;i<=CFD_URECORD_MAXNUM;i++)
    {
        gp_cacheactive_hashlist[i] = NULL;
        pthread_mutex_init(&(g_activeuser_lock[i]),NULL);
    }
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from rnode_uactive_tab;");
    if(sqlite3_get_table(g_rnodedb_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow ; i++ )
        {              
            id = atoi(dbResult[offset]);
            if(id > 0 && id < CFD_RNODE_MAXNUM)
            {
                pthread_mutex_lock(&g_activeuser_lock[id]);
                g_activeuser_list[id].id = id;
                g_activeuser_list[id].active_time = atoi(dbResult[offset+1]);
                g_activeuser_list[id].uindex = atoi(dbResult[offset+2]);
                g_activeuser_list[id].status = atoi(dbResult[offset+3]);
                g_activeuser_list[id].active_rid = atoi(dbResult[offset+4]);
                g_activeuser_list[id].rid_num = atoi(dbResult[offset+5]);
                if(dbResult[offset+6])
                {
                    strncpy(g_activeuser_list[id].uidstr,dbResult[offset+6],CFD_USER_PUBKEYLEN);
                }
                if(dbResult[offset+7])
                {
                    strncpy(g_activeuser_list[id].rid_liststr,dbResult[offset+7],PNR_USERNAME_MAXLEN);
                }
                if(g_activeuser_list[id].rid_num > 0 && strlen(g_activeuser_list[id].rid_liststr) > 0)
                {
                    cfd_rnodelist_string_to_array(g_activeuser_list[id].rid_liststr,g_activeuser_list[id].ridlist,&rid_num);
                }
                memcpy(&hashid,g_activeuser_list[id].uidstr,sizeof(uint16));
                hashid = (hashid & CFD_URECORD_MAXNUM);
                if(gp_cacheactive_hashlist[hashid] == NULL)
                {
                    gp_cacheactive_hashlist[hashid] = &g_activeuser_list[id];
                }
                pthread_mutex_unlock(&g_activeuser_lock[id]);
                g_cfdgeninfo.active_user++;
            }
            else
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get id failed");
            }
            offset += nColumn;
        }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uactive_dbupdate_byid
  Description:  插入新的用户活跃信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_dbupdate_byid(int id,int uindex,int active_rid,int lasttime,int node_num,char* ridlist)
{
    char *errmsg = NULL;
    char tmp_str[SQL_CMD_LEN] = {0};
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(id <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_dbupdate_lastactive_byid:bad input");
        return ERROR;
    } 
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    if(lasttime > 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uactive_tab set lastactive=%d",lasttime);
    }
    else
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_uactive_tab set lastactive=%d",(int)time(NULL));
    }
    if(uindex > 0)
    {
        memset(tmp_str,0,SQL_CMD_LEN);
        snprintf(tmp_str,SQL_CMD_LEN,",uindex=%d",uindex);
        strcat(sql_cmd,tmp_str);
    }
    if(active_rid > 0)
    {
        memset(tmp_str,0,SQL_CMD_LEN);
        snprintf(tmp_str,SQL_CMD_LEN,",activenode=%d",active_rid);
        strcat(sql_cmd,tmp_str);
    }
    if(ridlist != NULL)
    {
        memset(tmp_str,0,SQL_CMD_LEN);
        snprintf(tmp_str,SQL_CMD_LEN,",nodenum=%d,nodelist='%s'",node_num,ridlist);
        strcat(sql_cmd,tmp_str);
    }
    memset(tmp_str,0,SQL_CMD_LEN);
    snprintf(tmp_str,SQL_CMD_LEN," where id=%d",id);
    strcat(sql_cmd,tmp_str);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uactive_dbupdate_byid(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_uactive_lastactive_update_byid
  Description:  用户更新最新活跃节点
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_lastactive_update_byid(int id,int activetime,int last_rid)
{
    int newrondeid = TRUE,i =0;
    if(id <=0 || last_rid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_lastactive_update_byid:bad input");
        return ERROR;
    }
    for(i=0;i<g_activeuser_list[id].rid_num;i++)
    {
        if(last_rid == g_activeuser_list[id].ridlist[i])
        {
            newrondeid = FALSE;
            break;
        }
    }
    pthread_mutex_lock(&g_activeuser_lock[id]);
    if(activetime > 0)
    {
        g_activeuser_list[id].active_time = activetime;
    }
    g_activeuser_list[id].active_rid = last_rid;
    if(newrondeid == TRUE)
    {
        if(g_activeuser_list[id].rid_num < CFD_ACTIVERID_MAXNUM)
        {
            g_activeuser_list[id].ridlist[g_activeuser_list[id].rid_num] = last_rid;
            g_activeuser_list[id].rid_num++;
        }
        else
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d:%s) rid_num over",id,g_activeuser_list[id].uidstr);
            g_activeuser_list[id].ridlist[0]= last_rid;
        }
        cfd_rnodelist_array_to_string(g_activeuser_list[id].rid_num,g_activeuser_list[id].ridlist,g_activeuser_list[id].rid_liststr);
        cfd_uactive_dbupdate_byid(id,0,g_activeuser_list[id].active_rid,activetime,g_activeuser_list[id].rid_num,g_activeuser_list[id].rid_liststr);
    }
    else
    {
        cfd_uactive_dbupdate_byid(id,0,0,activetime,0,NULL);
    }
    pthread_mutex_unlock(&g_activeuser_lock[id]);
    return OK;
}
/**********************************************************************************
  Function:      cfd_uactive_dbget_func
  Description:   数据库查询活跃用户回掉
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
int32 cfd_uactive_dbget_func(void* obj, int n_columns, char** column_values,char** column_names)
{
    int i= 0;
    struct cfd_useractive_struct *puser = NULL;
    if(n_columns < 8 || obj == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_dbget_func get n_columns(%d)",n_columns);
        return ERROR;
    }
	puser = (struct cfd_useractive_struct*)obj;
    puser->id = atoi(column_values[i++]);
    puser->active_time = atoi(column_values[i++]);
    puser->uindex = atoi(column_values[i++]);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"AAAA:dbget user(%d) index(%d)",puser->id,puser->uindex);
    puser->status = atoi(column_values[i++]);
    puser->active_rid = atoi(column_values[i++]);
    puser->rid_num = atoi(column_values[i++]);
    if(column_values[i] != NULL)
    {
        strncpy(puser->uidstr,column_values[i],CFD_USER_PUBKEYLEN);
    }
    i++;
    if(column_values[i] != NULL)
    {
        strncpy(puser->rid_liststr,column_values[i],PNR_USERNAME_MAXLEN);
    }
#if 0
    if(puser->rid_num > 0 && strlen(puser->rid_liststr) > 0)
    {
        cfd_rnodelist_string_to_array(puser->rid_liststr,puser->ridlist,&i);
    }
#endif    
	return OK;
}

/**********************************************************************************
  Function:      cfd_uactive_dbget_buidstr
  Description:  根据用户id获取
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_dbget_buidstr(struct cfd_useractive_struct* puser)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(puser == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_dbget_buidstr:bad input");
        return ERROR;
    } 
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from rnode_uactive_tab where idstring='%s'",puser->uidstr);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uactive_dbget_buidstr:sqlcmd(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,cfd_uactive_dbget_func,puser,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_uactive_update_byidstr
  Description:  根据用户idstr更新用户在线状态
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_update_byidstr(struct cfd_innode_users_info* puser)
{
    int uid = 0;
    if(puser == NULL)
    {
        return ERROR;
    }
    cfd_uinfolistgetdbid_byuidstr(puser->idstr,&uid);
    if(uid > 0)
    {
        /*DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) active(%d:%d) new_active(%d:%d)",
            uid,g_activeuser_list[uid].active_rid,g_activeuser_list[uid].active_time,
            puser->active_rid,puser->last_active);*/
        pthread_mutex_lock(&g_activeuser_lock[uid]);
        if(g_activeuser_list[uid].active_time < puser->last_active)
        {
            if(puser->active_rid > 0 && puser->active_rid != g_activeuser_list[uid].active_rid)
            {
                pthread_mutex_unlock(&g_activeuser_lock[uid]);
                cfd_uactive_lastactive_update_byid(uid,puser->last_active,puser->active_rid);
                pthread_mutex_lock(&g_activeuser_lock[uid]);
            }
            else
            {
                g_activeuser_list[uid].active_time = puser->last_active;
                cfd_uactive_dbupdate_byid(uid,0,0,puser->last_active,0,NULL);
            }
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_uactive_update_byidstr:user(%d:%s) change lastactive(%d:%d)",
                uid,g_activeuser_list[uid].uidstr,g_activeuser_list[uid].active_rid,puser->last_active);
        }
        pthread_mutex_unlock(&g_activeuser_lock[uid]);
    }
    else if(g_rlist_node[CFD_RNODE_DEFAULT_RID].weight == CFD_RNODE_SERVER_WEIGHT)
    {
        uid = cfd_uinfolist_getidleid();
        if(uid > 0 && uid <= CFD_URECORD_MAXNUM)
        {
            cfd_uinfonode_addnew(uid,0,FALSE,0,0,puser->idstr,NULL,NULL,NULL,NULL);
            cfd_uactive_addnew(uid,0,puser->active_rid,puser->idstr);
        }
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_checklastactive_byuidstr
  Description:  根据uidstr查询对应用户是不是本地用户
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_checklastactive_byuidstr(char* p_uidstr,int* p_index,int* p_rid)
{
    uint16 hashid = 0;
    int id_strlen = 0;
    struct cfd_useractive_struct uactive;
    struct cfd_useractive_struct* puser = NULL;
    if(p_uidstr == NULL)
    {
        return ERROR;
    }
    memset(&uactive,0,sizeof(uactive));
    id_strlen = strlen(p_uidstr);
    if(id_strlen == TOX_ID_STR_LEN)
    {
        cfd_olduseridstr_getbytoxid(p_uidstr,uactive.uidstr);
    }
    else if(id_strlen == CFD_USER_PUBKEYLEN)
    {
        strcpy(uactive.uidstr,p_uidstr);
    }
    else
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_checklastactive_byuidstr:bad input(%d:%s)",id_strlen,p_uidstr);
        return ERROR;
    }
    g_checklocal_totalnum++;
    memcpy(&hashid,uactive.uidstr,sizeof(uint16));
    hashid = (hashid & CFD_URECORD_MAXNUM);
    if(gp_cacheactive_hashlist[hashid] != NULL)
    {
        if(strcmp(gp_cacheactive_hashlist[hashid]->uidstr,p_uidstr) == OK)
        {
            g_checklocal_cachematchnum ++;
            puser = gp_cacheactive_hashlist[hashid];
        }
    }
    if(puser == NULL)
    {
        cfd_uactive_dbget_buidstr(&uactive);
        if(uactive.id <= 0)
        {
            g_checklocal_getfail++;
            *p_rid = CFD_RNODE_RID_UNKNOWN;
            *p_index = 0;
            return ERROR;
        }
        else
        {
            puser = &uactive;
        }
    }
    if(puser->active_rid == CFD_RNODE_DEFAULT_RID)
    {
        *p_index = puser->uindex;
        *p_rid = CFD_RNODE_DEFAULT_RID;
    }
    else
    {
        *p_index = puser->uindex;
        *p_rid = puser->active_rid;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_getfriendid_byidstr
  Description:  根据用户id查找对应用户的friendid
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_getfriendid_byidstr(int userid,char* friend_idstr)
{
    int i = 0,idstr_len = 0;;
    char idstr[CFD_USER_PUBKEYLEN+1] = {0};
    char* pidstr = NULL;
    if( userid <=0 || userid > PNR_IMUSER_MAXNUM || friend_idstr == NULL)
    {
        return -1;
    }
    idstr_len = strlen(friend_idstr);
    if(idstr_len == TOX_ID_STR_LEN)
    {
        cfd_olduseridstr_getbytoxid(friend_idstr,idstr);
        pidstr = idstr;
    }
    else
    {
        pidstr = friend_idstr;
    }
    for(i=0;i<PNR_IMUSER_FRIENDS_MAXNUM;i++)
    {
        if(strcmp(pidstr,g_imusr_array.usrnode[userid].friends[i].user_toxid) == OK)
        {
            return i;
        }
    }
    return -1;
}
/**********************************************************************************
  Function:      cfd_uactive_addnew
  Description:  插入新的用户活跃信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_uactive_addnew(int id,int index,int active_rid,char* uidstr)
{
    uint16 hashid = 0;
    if(id <= 0 || id > CFD_URECORD_MAXNUM || uidstr == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_addnew:bad input");
        return ERROR;
    }
    if(g_activeuser_list[id].id != 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uactive_addnew:uid(%d) is not null",id);
        return ERROR;
    }
    pthread_mutex_lock(&g_activeuser_lock[id]);
    g_activeuser_list[id].id = id;
    g_activeuser_list[id].active_time = (int)time(NULL);
    g_activeuser_list[id].uindex = index;
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"AAAA:add user(%d) index(%d)",id,g_activeuser_list[id].uindex);
    g_activeuser_list[id].status= 0;
    g_activeuser_list[id].active_rid = active_rid;
    g_activeuser_list[id].rid_num = 1;
    strcpy(g_activeuser_list[id].uidstr,uidstr);
    g_activeuser_list[id].ridlist[0] = active_rid;
    cfd_rnodelist_array_to_string(g_activeuser_list[id].rid_num,g_activeuser_list[id].ridlist,g_activeuser_list[id].rid_liststr);
    cfd_uactive_newuser_dbinsert(&g_activeuser_list[id]);
    memcpy(&hashid,uidstr,sizeof(uint16));
    hashid = (hashid & CFD_URECORD_MAXNUM);
    if(gp_cacheactive_hashlist[hashid] == NULL)
    {
        gp_cacheactive_hashlist[hashid] = &g_activeuser_list[id];
    }
    pthread_mutex_unlock(&g_activeuser_lock[id]);
    return OK;
}

/**********************************************************************************
  Function:      cfd_getactiveuser_byuidstr
  Description:  根据uidstr查询对应用户
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        -1:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
struct cfd_useractive_struct* cfd_getactiveuser_byuidstr(char* p_uidstr)
{
    uint16 hashid = 0;
    int db_id = -1;
    int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};

    if(p_uidstr == NULL)
    {
        return NULL;
    }
    g_getactiveuser_totalnum++;
    memcpy(&hashid,p_uidstr,sizeof(uint16));
    hashid = (hashid & CFD_URECORD_MAXNUM);
    if(gp_cacheactive_hashlist[hashid] != NULL)
    {
        if(strcmp(gp_cacheactive_hashlist[hashid]->uidstr,p_uidstr) == OK)
        {
            g_getactiveuser_cachematchnum ++;
            return gp_cacheactive_hashlist[hashid];
        }
    }
    //rnode_uactive_tab(id,lastactive,uindex,status,activenode,nodenum,idstring,nodelist);
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from rnode_uactive_tab where idstring='%s';",p_uidstr);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&db_id,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql(%s) get cur_status failed",sql_cmd);
        sqlite3_free(errMsg);
        return NULL;
    }
    if(db_id >= 0 && db_id < CFD_URECORD_MAXNUM)
    {
        return &g_activeuser_list[db_id];
    }
    g_getactiveuser_getfail++;
    return NULL;
}

/**********************************************************************************
  Function:      cfd_friendrecords_init
  Description:  friendrecords 初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_friendrecords_init(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i,uindex;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    memset(&g_friendrecords,0,sizeof(struct cfd_friends_record)*(PNR_IMUSER_MAXNUM+1)*(PNR_IMUSER_FRIENDS_MAXNUM+1));
    //rnode_friends_tab(id integer primary key autoincrement,createtime,status,uindex,uid,fid,oneway,uidstr,fidstr,remark,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from rnode_friends_tab;");
    if(sqlite3_get_table(g_rnodedb_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow; i++ )
        {        
            uindex = atoi(dbResult[offset+3]);
            if(uindex > 0 && uindex <= PNR_IMUSER_MAXNUM)
            {
                g_friendrecords[uindex][i].id = atoi(dbResult[offset]);
                g_friendrecords[uindex][i].createtime = atoi(dbResult[offset+1]);
                g_friendrecords[uindex][i].status = atoi(dbResult[offset+2]);
                g_friendrecords[uindex][i].index = uindex;
                g_friendrecords[uindex][i].uid = atoi(dbResult[offset+4]);
                g_friendrecords[uindex][i].fid = atoi(dbResult[offset+5]);
                g_friendrecords[uindex][i].oneway = atoi(dbResult[offset+6]);
                if(dbResult[offset+7])
                {
                    strncpy(g_friendrecords[uindex][i].uidstr,dbResult[offset+7],CFD_USER_PUBKEYLEN);
                }
                if(dbResult[offset+8])
                {
                    strncpy(g_friendrecords[uindex][i].fidstr,dbResult[offset+8],CFD_USER_PUBKEYLEN);
                }
                if(dbResult[offset+9])
                {
                    strncpy(g_friendrecords[uindex][i].remark,dbResult[offset+9],PNR_USERNAME_MAXLEN);
                }
                //info暂时没用
            }
            offset += nColumn;
        }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnode_changerecord_dbinsert
  Description:  插入新的用户状态变更记录
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_changerecord_dbinsert(struct cfd_changelog_info* p_record)
{
    char *errmsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_record == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_changerecord_dbinsert:bad input");
        return ERROR;
    }
    //先检查当前记录是否已经存在
    //rnode_changelog_tab(id integer primary key autoincrement,timestamp,type,uindex,seq,action,version,srcrid,dstrid,srcuid,dstuid,info)
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from rnode_changelog_tab where uindex=%d and type=%d and seq=%d;",
    p_record->index,p_record->type,p_record->seq);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&count,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_changerecord_dbinsert friends(%s->%s) exsit",p_record->src_uid,p_record->dst_uid);
        return ERROR;
    }     
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_changelog_tab values(NULL,%d,%d,%d,%d,%d,%d,%d,%d,'%s','%s','%s');",
        p_record->timestamp,p_record->type,p_record->index,p_record->seq,p_record->action,p_record->version,
        p_record->src_rid,p_record->dst_rid,p_record->src_uid,p_record->dst_uid,p_record->info);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_changerecord_dbinsert(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnode_friendsrecord_dbinsert
  Description:  插入新的用户好友记录
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_friendsrecord_dbinsert(struct cfd_friends_record *p_record)
{
    char *errmsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(p_record == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_friendsrecord_dbinsert:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_friends_tab(id integer primary key autoincrement,createtime,status,uindex,uid,fid,oneway,uidstr,fidstr,remark,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from rnode_friends_tab where uid=%d and fid=%d;",p_record->uid,p_record->fid);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&count,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_friendsrecord_dbinsert friends(%s->%s) exsit",p_record->uidstr,p_record->fidstr);
        return ERROR;
    }     
    if(p_record->createtime > 0)
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_friends_tab values(NULL,%d,%d,%d,%d,%d,%d,'%s','%s','%s','');",
            p_record->createtime,p_record->status,p_record->index,p_record->uid,p_record->fid,p_record->oneway,p_record->uidstr,p_record->fidstr,p_record->remark);
    }
    else
    {
        snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_friends_tab values(NULL,%d,%d,%d,%d,%d,%d,'%s','%s','%s','');",
            (int)time(NULL),p_record->status,p_record->index,p_record->uid,p_record->fid,p_record->oneway,p_record->uidstr,p_record->fidstr,p_record->remark);
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnode_friendsrecord_dbinsert(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_friendsrecord_add
  Description:  插入新的用户好友记录
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_friendsrecord_add(int index,char* puser,char* pfriend,char* remark)
{
    struct cfd_friends_record new_friend;
    struct cfd_changelog_info changeinfo;

    memset(&new_friend,0,sizeof(new_friend));
    if(puser == NULL || pfriend == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_friendsrecord_add:bad input");
        return ERROR;
    }
    cfd_toxidformatidstr(puser,new_friend.uidstr);
    cfd_toxidformatidstr(pfriend,new_friend.fidstr);
    new_friend.index = index;
    cfd_uinfolistgetdbid_byuidstr(new_friend.uidstr,&new_friend.uid);
    cfd_uinfolistgetdbid_byuidstr(new_friend.fidstr,&new_friend.fid);
    cfd_rnode_friendsrecord_dbinsert(&new_friend);
    //记录一条changelog
    memset(&changeinfo,0,sizeof(changeinfo));
    changeinfo.index = index;
    changeinfo.type = CFD_CHANGELOG_TYPE_USERFRIENDS;
    changeinfo.action = CFD_FRIENDINFO_ACTION_NEWFRIEND;
    cfd_uinfoseq_dbget_byindex(changeinfo.index,changeinfo.type,&changeinfo.seq);
    changeinfo.seq++;
    changeinfo.timestamp = (int)time(NULL);
    changeinfo.src_rid = CFD_RNODE_DEFAULT_RID;
    cfd_uactive_lastrid_dbget_byuidstr(new_friend.fidstr,&changeinfo.dst_rid);
    strcpy(changeinfo.src_uid,new_friend.uidstr);
    strcpy(changeinfo.dst_uid,new_friend.fidstr);
    strcpy(changeinfo.info,new_friend.remark);
    if(cfd_rnode_changerecord_dbinsert(&changeinfo) == OK)
    {
        cfd_uinfoseq_dbupdate_byindex(changeinfo.index,changeinfo.type,changeinfo.seq);
    }
    else
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_changerecord_dbinsert failed");
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_friendsrecord_delete
  Description:  删除的用户好友记录
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_friendsrecord_delete(char* pfrom,char* pfriend,int oneway)
{
	int8* errMsg = NULL;
	char sql_cmd[SQL_CMD_LEN] = {0};
    char from_uidstr[CFD_USER_PUBKEYLEN+1] = {0};
    char friend_uidstr[CFD_USER_PUBKEYLEN+1] = {0};
    struct cfd_changelog_info changeinfo;

    if(pfrom == NULL || pfriend== NULL)
    {
        return ERROR;
    }
    cfd_toxidformatidstr(pfrom,from_uidstr);
    cfd_toxidformatidstr(pfriend,friend_uidstr);
    if (oneway) 
    {
		snprintf(sql_cmd,SQL_CMD_LEN,"update rnode_friends_tab set oneway=%d where uidstr='%s' and fidstr='%s';",oneway, from_uidstr,friend_uidstr);
	} 
    else 
	{
		snprintf(sql_cmd,SQL_CMD_LEN,"delete from rnode_friends_tab where uidstr='%s' and fidstr='%s';",from_uidstr,friend_uidstr);
	}
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errMsg);
        sqlite3_free(errMsg);
        return ERROR;
    }
    //记录一条changelog
    if(oneway == 0)
    {
        memset(&changeinfo,0,sizeof(changeinfo));
        changeinfo.index = cfd_getindexbyidstr(from_uidstr);
        changeinfo.type = CFD_CHANGELOG_TYPE_USERFRIENDS;
        changeinfo.action = CFD_FRIENDINFO_ACTION_DELFRIEND;
        cfd_uinfoseq_dbget_byindex(changeinfo.index,changeinfo.type,&changeinfo.seq);
        changeinfo.seq++;
        changeinfo.timestamp = (int)time(NULL);
        changeinfo.src_rid = CFD_RNODE_DEFAULT_RID;
        cfd_uactive_lastrid_dbget_byuidstr(friend_uidstr,&changeinfo.dst_rid);
        strcpy(changeinfo.src_uid,from_uidstr);
        strcpy(changeinfo.dst_uid,friend_uidstr);
        if(cfd_rnode_changerecord_dbinsert(&changeinfo) == OK)
        {
            cfd_uinfoseq_dbupdate_byindex(changeinfo.index,changeinfo.type,changeinfo.seq);
        }
        else
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_changerecord_dbinsert failed");
        }
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnode_friendsrecord_dbinit
  Description:  从friends_tbl创建初始rnode_friends_tab 
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_friendsrecord_dbinit(void)
{
    char **dbResult; 
    char *errmsg = NULL;
    int nRow, nColumn,i;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_friends_record tmpnode;
    struct cfd_changelog_info changeinfo;

    memset(&changeinfo,0,sizeof(changeinfo));
    changeinfo.type = CFD_CHANGELOG_TYPE_USERFRIENDS;
    changeinfo.action = CFD_FRIENDINFO_ACTION_NEWFRIEND;
    changeinfo.src_rid = CFD_RNODE_DEFAULT_RID;
    //提取旧的friends_tbl表中数据    
    snprintf(sql_cmd,SQL_CMD_LEN,"select id,timestamp,oneway,userkey,remarks from friends_tbl;");
    if(sqlite3_get_table(g_friendsdb_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow && i < CFD_RNODE_MAXNUM; i++ )
        {               
            memset(&tmpnode,0,sizeof(tmpnode));
            tmpnode.index = atoi(dbResult[offset]);
            tmpnode.createtime = atoi(dbResult[offset+1]);
            tmpnode.oneway = atoi(dbResult[offset+2]);
            if(dbResult[offset+3])
            {
                strncpy(tmpnode.fidstr,dbResult[offset+3],CFD_USER_PUBKEYLEN);
            }
            if(dbResult[offset+4])
            {
                strncpy(tmpnode.remark,dbResult[offset+4],PNR_USERNAME_MAXLEN);
            }
            offset += nColumn;
            cfd_uinfodbid_dbget_byindex(tmpnode.index,&tmpnode.uid);
            cfd_uinfodbid_dbget_byidstr(tmpnode.fidstr,&tmpnode.fid);
            cfd_uinfouidstr_dbget_byuindex(tmpnode.index,tmpnode.uidstr);
            if(tmpnode.fid <= 0 || strlen(tmpnode.uidstr) <= 0 
                || cfd_rnode_friendsrecord_dbinsert(&tmpnode) != OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_friendsrecord_dbinit failed");
            }
            else
            {
                //记录一条changelog
                changeinfo.index = tmpnode.index;
                cfd_uinfoseq_dbget_byindex(changeinfo.index,changeinfo.type,&changeinfo.seq);
                changeinfo.seq++;
                cfd_uactive_lastrid_dbget_byuid(tmpnode.fid,&changeinfo.dst_rid);
                changeinfo.timestamp = tmpnode.createtime;
                strcpy(changeinfo.src_uid,tmpnode.uidstr);
                strcpy(changeinfo.dst_uid,tmpnode.fidstr);
                strcpy(changeinfo.info,tmpnode.remark);
                if(cfd_rnode_changerecord_dbinsert(&changeinfo) == OK)
                {
                    cfd_uinfoseq_dbupdate_byindex(changeinfo.index,changeinfo.type,changeinfo.seq);
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_rnode_changerecord_dbinsert failed");
                }
            }
        }
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_olduseridstr_dbgetbytoxid
  Description:  老用户根据toxid查用户idstr
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_olduseridstr_dbgetbytoxid(char* p_toxid,char* p_idstr)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct db_string_ret db_ret;

    if(p_toxid == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_olduseridstr_dbgetbytoxid:bad input");
        return ERROR;
    }
    db_ret.buf_len = CFD_USER_PUBKEYLEN;
    db_ret.pbuf = p_idstr;
    //rnode_oldusermap_tab(id integer primary key autoincrement,uindex,nodeid,idstr,toxid,devid);
    snprintf(sql_cmd,SQL_CMD_LEN,"select idstr from rnode_oldusermap_tab where toxid='%s';",p_toxid);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_singstr_result,&db_ret,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfouidstr_dbget_byuindex");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_olduser_idstr_getbytoxid
  Description:  老用户映射关系初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_olduseridstr_getbytoxid(char* p_toxid,char* p_idstr)
{
    uint16 hashid = 0;
    if(p_toxid == NULL)
    {
        return ERROR;
    }
    g_oldusers_checktotalnum++;
    memcpy(&hashid,p_toxid,sizeof(uint16));
    hashid = (hashid & CFD_RNODE_MAXNUM);
    if(gp_oldusers_cachebytoxid[hashid] != NULL && strcmp(p_toxid,gp_oldusers_cachebytoxid[hashid]->toxid) == OK)
    {
        g_oldusers_cachematchnum++;
        strcpy(p_idstr,gp_oldusers_cachebytoxid[hashid]->idstr);
        return OK;
    }
    cfd_olduseridstr_dbgetbytoxid(p_toxid,p_idstr);
    if(strlen(p_idstr) == CFD_USER_PUBKEYLEN)
    {
        return OK;
    }
    //DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_olduseridstr_getbytoxid tox(%s) find failed",p_toxid);
    g_oldusers_checkfail++;
    return ERROR;
}
/**********************************************************************************
  Function:      cfd_oldusermapping_init
  Description:  老用户映射关系初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_oldusermapping_init(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i;
    int offset=0;
    uint16 hashid = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_olddata_mapping* puser = NULL;

    //初始化
    memset(&g_oldusers,0,sizeof(struct cfd_olddata_mapping)*(CFD_RNODE_MAXNUM+1));
    for(i = 0 ; i<= PNR_IMUSER_MAXNUM;i++)
    {
        gp_localoldusers[i] = NULL;
    }
    for(i = 0 ; i<= CFD_RNODE_MAXNUM;i++)
    {
        gp_oldusers_cachebytoxid[i] = NULL;
    }
    //rnode_oldusermap_tab(id integer primary key autoincrement,uindex,nodeid,idstr,toxid,devid);
    snprintf(sql_cmd,SQL_CMD_LEN,"select * from rnode_oldusermap_tab;");
    if(sqlite3_get_table(g_rnodedb_handle, sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从offset开始呀
        for( i = 0; i < nRow && i < CFD_URECORD_MAXNUM; i++ )
        {               
            puser = &g_oldusers[i];
            puser->id = atoi(dbResult[offset]);
            puser->index = atoi(dbResult[offset+1]);
            puser->nodeid = atoi(dbResult[offset+2]);
            if(dbResult[offset+3])
            {
                strncpy(puser->idstr,dbResult[offset+3],CFD_USER_PUBKEYLEN);
            }
            if(dbResult[offset+4])
            {
                strncpy(puser->toxid,dbResult[offset+4],TOX_ID_STR_LEN);
            }
            if(dbResult[offset+5])
            {
                strncpy(puser->devid,dbResult[offset+5],TOX_ID_STR_LEN);
            }
            if(puser->index > 0 && puser->index <= PNR_IMUSER_MAXNUM)
            {
                if(gp_localoldusers[puser->index] == NULL)
                {
                    gp_localoldusers[puser->index] = puser;
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_oldusermapping_init: index(%d) repeat",puser->index);
                }
            }
            memcpy(&hashid,puser->toxid,sizeof(uint16));
            hashid = (hashid & CFD_RNODE_MAXNUM);
            if(gp_oldusers_cachebytoxid[hashid] == NULL)
            {
                gp_oldusers_cachebytoxid[hashid] = puser;
            }
            offset += nColumn;
        }
        sqlite3_free_table(dbResult);
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_oldusermapping_dbinsert
  Description:  插入一条老用户映射信息
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_oldusermapping_dbinsert(struct cfd_olddata_mapping *puser)
{
    char *errmsg = NULL;
    int count = 0;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(puser == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_oldusermapping_dbinsert:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //rnode_oldusermap_tab(id integer primary key autoincrement,uindex,nodeid,idstr,toxid,devid);
    snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) from rnode_oldusermap_tab where toxid='%s';",puser->toxid);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,dbget_int_result,&count,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get count failed");
        sqlite3_free(errmsg);
        return ERROR;
    }
    if(count > 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_oldusermapping_dbinsert user(%s) exsit",puser->idstr);
        return ERROR;
    }     
    snprintf(sql_cmd,SQL_CMD_LEN,"insert into rnode_oldusermap_tab values(NULL,%d,%d,'%s','%s','%s');",
        puser->index,puser->nodeid,puser->idstr,puser->toxid,puser->devid);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_oldusermapping_dbinsert(%s)",sql_cmd);
    if(sqlite3_exec(g_rnodedb_handle,sql_cmd,0,0,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/***********************************************************************************
  Function:      cfd_msglog_update_byoldmsgtbl
  Description: 根据旧记录刷新
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
int cfd_msglog_update_byoldmsgtbl(int index,struct im_sendmsg_msgstruct* pmsg)
{
	int8* errMsg = NULL;
	char sql_cmd[MSGSQL_CMD_LEN] = {0};
    char* p_sql = NULL;
    int sql_len = MSGSQL_CMD_LEN;
    int sql_malloc_flag = FALSE;
    
    if (pmsg == NULL) 
    {
        return ERROR;
    }
    if(strlen(pmsg->msg_buff) > SQL_CMD_LEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_msglog_update_byoldmsgtbl:malloc failed");
            return ERROR;
        }
        sql_malloc_flag = TRUE;
        sql_len = MSGSQL_ALLOC_MAXLEN;
    }
    else
    {
        p_sql = sql_cmd;
    } 	
    //cfd_msglog_tbl(userindex,timestamp,id integer primary key autoincrement,logid,msgtype,status,from,to,msg,filepath,filesize,skey,dkey)
    snprintf(p_sql, sql_len, "insert into cfd_msglog_tbl "
        "(userindex,timestamp,id,logid,msgtype,status,from_user,to_user,msg,filepath,filesize,sign,nonce,prikey) "
        "values(%d,%d,%d,%d,%d,%d,'%s','%s','%s','%s',%d,'%s','%s','%s');",
        index,pmsg->timestamp,pmsg->db_id,pmsg->log_id,pmsg->msgtype,pmsg->msg_status,pmsg->fromuser,pmsg->touser,
        pmsg->msg_buff,pmsg->ext,pmsg->ext2,pmsg->sign,pmsg->nonce,pmsg->prikey);
	DEBUG_PRINT(DEBUG_LEVEL_INFO, "cfd_msglog_update_byoldmsgtbl:sql_cmd(%s)",p_sql);
    if (sqlite3_exec(g_msglogdb_handle[index], p_sql, 0, 0, &errMsg)) 
    {
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
  Function:      cfd_msglogtbl_dbinit
  Description:  消息日志记录,重新起一个表与旧表区别
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
int cfd_msglogtbl_dbinit(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i,index = 0,count = 0;
    int offset=0;
    char db_file[PNR_FILENAME_MAXLEN+1] = {0};
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct im_sendmsg_msgstruct* ptmp_msg = NULL;

    ptmp_msg = (struct im_sendmsg_msgstruct *)calloc(1, sizeof(*ptmp_msg));
    if (!ptmp_msg) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err2");
        return ERROR;
    }

    for(index=0;index<PNR_IMUSER_MAXNUM;index++)
    {
        snprintf(db_file,PNR_FILENAME_MAXLEN,"%suser%d/pnrouter_msglog.db",DAEMON_PNR_USERDATA_DIR,index);
        if(access(db_file, F_OK) == OK)
        {
            //如果当前有记录
            if (sqlite3_open(db_file, &g_msglogdb_handle[index]) != OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_msglog_tbl_dbinit failed");
                free(ptmp_msg);
                return ERROR;
            }
            //初始化新版groupinfo_tbl表
            snprintf(sql_cmd,SQL_CMD_LEN,"select count(*) FROM sqlite_master WHERE type=\"table\" AND name = \"cfd_msglog_tbl\";");
            if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&count,&errmsg))
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sqlite cmd(%s) err(%s)",sql_cmd,errmsg);
                sqlite3_free(errmsg);
                return ERROR;
            } 
            if(count <= 0)
            {
                snprintf(sql_cmd,SQL_CMD_LEN,"create table cfd_msglog_tbl("
        		    "userindex,timestamp,id integer primary key autoincrement,"
        		    "logid,msgtype,status,from_user,to_user,msg,filepath,filesize,sign,nonce,prikey);");
                if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errmsg))
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errmsg);
                    free(ptmp_msg);
                    sqlite3_free(errmsg);
                    return ERROR;
                }
            }
            else
            {
                snprintf(sql_cmd,SQL_CMD_LEN,"delete from cfd_msglog_tbl;");
                if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errmsg))
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errmsg);
                    free(ptmp_msg);
                    sqlite3_free(errmsg);
                    return ERROR;
                }
            }
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,logid,timestamp,status,"
				"from_user,to_user,msg,msgtype,ext,ext2,sign,nonce,prikey from msg_tbl;");
            if(sqlite3_get_table(g_msglogdb_handle[index], sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow && i < CFD_URECORD_MAXNUM; i++ )
                {      
                    memset(ptmp_msg,0,sizeof(struct im_sendmsg_msgstruct));
                    ptmp_msg->db_id = atoi(dbResult[offset]);
                    ptmp_msg->log_id = atoi(dbResult[offset+1]);
                    ptmp_msg->timestamp = atoi(dbResult[offset+2]);
                    ptmp_msg->msg_status = atoi(dbResult[offset+3]);
                    if(dbResult[offset+4])
                    {
                        strncpy(ptmp_msg->fromuser_toxid,dbResult[offset+4],TOX_ID_STR_LEN);
                    }
                    if(dbResult[offset+5])
                    {
                        strncpy(ptmp_msg->touser_toxid,dbResult[offset+5],TOX_ID_STR_LEN);
                    }
                    if(dbResult[offset+6])
                    {
                        strncpy(ptmp_msg->msg_buff,dbResult[offset+6],IM_MSG_PAYLOAD_MAXLEN);
                    }
    				ptmp_msg->msgtype = atoi(dbResult[offset+7]);
                    if(dbResult[offset+8])
                    {
                        strncpy(ptmp_msg->ext,dbResult[offset+8],IM_MSG_MAXLEN);
                    }
                    ptmp_msg->ext2 = atoi(dbResult[offset+9]);
                    if(dbResult[offset+10])
                    {
                        strncpy(ptmp_msg->sign,dbResult[offset+10],PNR_RSA_KEY_MAXLEN);
                    }
                    if(dbResult[offset+11])
                    {
                        strncpy(ptmp_msg->nonce,dbResult[offset+11],PNR_RSA_KEY_MAXLEN);
                    }
                    if(dbResult[offset+12])
                    {
                        strncpy(ptmp_msg->prikey,dbResult[offset+12],PNR_RSA_KEY_MAXLEN);
                    }
                    cfd_olduseridstr_getbytoxid(ptmp_msg->fromuser_toxid,ptmp_msg->fromuser);
                    cfd_olduseridstr_getbytoxid(ptmp_msg->touser_toxid,ptmp_msg->touser);
                    cfd_msglog_update_byoldmsgtbl(index,ptmp_msg);
                    offset += nColumn;
                }
                sqlite3_free_table(dbResult);
            }
             //获取当前db的id最大值,来判断是否有filelist表
            memset(sql_cmd,0,SQL_CMD_LEN);
            snprintf(sql_cmd,SQL_CMD_LEN,"SELECT max(id) sqlite_sequence from filelist_tbl;");
            if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&count,&errmsg))
            {
                sqlite3_free(errmsg);
                memset(sql_cmd,0,SQL_CMD_LEN);
            }
            else
            {
                snprintf(sql_cmd,SQL_CMD_LEN,"drop table filelist_tbl;");
                if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errmsg))
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errmsg);
                    sqlite3_free(errmsg);
                    return ERROR;
                }
            }
            //获取当前db的id最大值,来判断是否有cfd_filelist_tbl表
            memset(sql_cmd,0,SQL_CMD_LEN);
            snprintf(sql_cmd,SQL_CMD_LEN,"SELECT max(id) sqlite_sequence from cfd_filelist_tbl;");
            if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,&count,&errmsg))
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errmsg);
                sqlite3_free(errmsg);
                memset(sql_cmd,0,SQL_CMD_LEN);
                snprintf(sql_cmd,SQL_CMD_LEN,"create table cfd_filelist_tbl("
        		    "id integer primary key autoincrement,userindex,timestamp,version,depens,"
        		    "msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey);");
                if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,0,0,&errmsg))
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) sqlite cmd(%s) err(%s)",index,sql_cmd,errmsg);
                    sqlite3_free(errmsg);
                    return ERROR;
                }
            }
        }
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_filelist_dbgetfid_byname
  Description:  根据用户idstring查询rnode_uinfo_tab的index
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_dbgetfileid_byname(int index,int depens,int pathid,char* fname,int* fid)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(fname == NULL || fid == NULL || index <=0 || index > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_dbgetfid_byname:bad input");
        return ERROR;
    }
    //先检查当前用户记录是否已经存在
    //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select fileid from cfd_filelist_tbl where depens=%d and pathid=%d and fname='%s';",depens,pathid,fname);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,fid,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_dbgetfid_byname");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_filelist_dbgetdbid_byfileid
  Description:  根据用户idstring查询rnode_uinfo_tab的index
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_dbgetdbid_byfileid(int index,int depens,int pathid,int fileid,int* pid)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(pid == NULL || index <=0 || index > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_dbgetdbid_byname:bad input");
        return ERROR;
    }
    //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from cfd_filelist_tbl where depens=%d and pathid=%d and fileid=%d;",depens,pathid,fileid);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,pid,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_dbgetdbid_byname");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_filelist_dbgetdbid_byname
  Description:  根据用户idstring查询rnode_uinfo_tab的index
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_dbgetdbid_byname(int index,int depens,int pathid,char* fname,int* pid)
{
    char *errmsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(fname == NULL || pid == NULL || index <=0 || index > PNR_IMUSER_MAXNUM)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_dbgetdbid_byname:bad input");
        return ERROR;
    }
    //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from cfd_filelist_tbl where depens=%d and pathid=%d and fname='%s';",depens,pathid,fname);
    if(sqlite3_exec(g_msglogdb_handle[index],sql_cmd,dbget_int_result,pid,&errmsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_dbgetdbid_byname");
        sqlite3_free(errmsg);
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_filepath_count
  Description:  file list 数据
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_count(int index,int pathid,int add_flag,int size,int lasttime)
{
    if(pathid <= 0 || pathid > CFD_PATHS_MAXNUM || index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    if(add_flag == TRUE)
    {
        g_filelists[index].files_num++;
        g_filelists[index].total_size += size;
        g_filelists[index].paths[pathid].filenum++;
        g_filelists[index].paths[pathid].size += size;
    }
    else
    {
        g_filelists[index].files_num--;
        g_filelists[index].total_size -= size;
        g_filelists[index].paths[pathid].filenum--;
        g_filelists[index].paths[pathid].size -= size;
    }
    if(g_filelists[index].paths[pathid].lasttime < lasttime)
    {
        g_filelists[index].paths[pathid].lasttime = lasttime;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_filelist_addpath
  Description:   数据
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_addpath(int index,int pathid,int depens,char* pathname)
{
    int src_from = 0;
    if(pathid <= 0 || pathid > CFD_PATHS_MAXNUM || index <= 0 || index > PNR_IMUSER_MAXNUM || pathname == NULL)
    {
        return ERROR;
    }
    g_filelists[index].paths[pathid].depens = depens;
    g_filelists[index].paths[pathid].type = PNR_IM_MSGTYPE_USRPATH;
    g_filelists[index].paths[pathid].pathid = pathid;
    g_filelists[index].paths[pathid].lasttime = (int)time(NULL);
    strcpy(g_filelists[index].paths[pathid].name,pathname);
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) create filepath(%d:%s)",index,pathid,g_filelists[index].paths[pathid].name);
    if(depens == CFD_DEPNEDS_ALBUM)
    {
        src_from = PNR_FILE_SRCFROM_ALBUM;
    }
    else if(depens == CFD_DEPNEDS_FOLDER)
    {
        src_from = PNR_FILE_SRCFROM_FOLDER;
    }
    else
    {
        src_from = PNR_FILE_SRCFROM_WXPATH;
    }
    pnr_filelist_dbinsert(index,0,g_filelists[index].paths[pathid].type,depens,src_from,0,pathid,0,
        "","",pathname,"","","","","");
    cfd_filelist_dbgetdbid_byname(index,depens,pathid,pathname,&g_filelists[index].paths[pathid].id);
    return OK;
}
/**********************************************************************************
  Function:      cfd_filelist_rename
  Description:   数据
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_rename(int index,int type,int depens,int pid,int fid,char* newname,char*oldname)
{
    int getid = -1,i = 0;
    if(newname  == NULL || oldname == NULL || index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        return CFD_FILEACTION_RETURN_BADPARAMS;
    }
    if(pid <= 0 || pid > CFD_PATHS_MAXNUM)
    {
        return CFD_FILEACTION_RETURN_BADPARAMS;
    }
    //文件更名
    if(type == CFD_FILEACTION_TYPE_FILE)
    {
        if(strlen(newname) <= 0)
        {
            return CFD_FILEACTION_RETURN_BADPARAMS;
        }
        cfd_filelist_dbgetfileid_byname(index,depens,pid,newname,&getid);
        if(getid >= 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get newfilename(%s) exsit fileid(%d)",newname,getid);
            return CFD_FILEACTION_RETURN_FILENAMEREPEAT;
        }
        getid = -1;
        cfd_filelist_dbgetfileid_byname(index,depens,pid,oldname,&getid);
        if(getid < 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get oldfile(%s) failed",oldname);
            return CFD_FILEACTION_RETURN_NOTARGET;
        }
        memset(g_filelists[index].files[getid].name,0,PNR_FILENAME_MAXLEN);
        strcpy(g_filelists[index].files[getid].name,newname);
        g_filelists[index].files[getid].timestamp = (int)time(NULL);
        pnr_filelist_dbupdate_filename_byid(index,g_filelists[index].files[getid].id,newname);
    }
    else
    {
        if(strcmp(g_filelists[index].paths[pid].name,oldname) != OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get oldfile(%s) failed",oldname);
            return CFD_FILEACTION_RETURN_NOTARGET;
        }
        if(g_filelists[index].paths[pid].type == PNR_IM_MSGTYPE_SYSPATH)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get oldfile(%s) is syspath",oldname);
            return CFD_FILEACTION_RETURN_NOTARGET;
        }
        for(i = 1;i<=CFD_PATHS_MAXNUM;i++)
        {
            if(strcmp(g_filelists[index].paths[i].name,newname) == OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get oldfile(%s) is syspath",oldname);
                return CFD_FILEACTION_RETURN_FILENAMEREPEAT;
            }
        }            
        memset(g_filelists[index].paths[pid].name,0,PNR_FILENAME_MAXLEN);
        strcpy(g_filelists[index].paths[pid].name,newname);
        g_filelists[index].paths[pid].lasttime = (int)time(NULL);
        pnr_filelist_dbupdate_filename_byid(index,g_filelists[index].paths[pid].id,newname);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_filelist_delete
  Description:   数据
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_delete(int index,int type,int depens,int pid,int fid,char*name)
{
    int getid = -1;
    char fullpath[PNR_FILEPATH_MAXLEN+1] = {0};
    if(name == NULL || index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        return CFD_FILEACTION_RETURN_BADPARAMS;
    }
    if(pid <= 0 || pid > CFD_PATHS_MAXNUM)
    {
        return CFD_FILEACTION_RETURN_BADPARAMS;
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_filelist_delete:user(%d) delete type(%d) file(%d:%s)",index,type,pid,name);
    //文件更名
    if(type == CFD_FILEACTION_TYPE_FILE)
    {
        if(strlen(name) <= 0)
        {
            return CFD_FILEACTION_RETURN_BADPARAMS;
        }
        cfd_filelist_dbgetfileid_byname(index,depens,pid,name,&getid);
        if(getid < 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_filelist_delete:get filename(%d:%d:%s) failed",depens,pid,name);
            return CFD_FILEACTION_RETURN_FILENAMEREPEAT;
        }
        pnr_filelist_dbdelete_byid(index,g_filelists[index].files[getid].id);
        cfd_filelist_count(index,pid,FALSE,g_filelists[index].files[getid].size,(int)time(NULL));
        if(strlen(g_filelists[index].files[getid].path) > 0)
        {
            strcpy(fullpath,WS_SERVER_INDEX_FILEPATH);
            strcat(fullpath,g_filelists[index].files[getid].path);
            if (access(fullpath, F_OK) == OK)
            {
                unlink(fullpath);
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_filelist_delete:user(%d) delete delete file(%d:%s)",index,getid,fullpath);
            }
        }
        memset(&g_filelists[index].files[getid],0,sizeof(struct cfd_fileinfo_struct));
    }
    else
    {
        if(strcmp(g_filelists[index].paths[pid].name,name) != OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) get path(%d:%s:%s) failed",index,pid,name,g_filelists[index].paths[pid].name);
            return CFD_FILEACTION_RETURN_NOTARGET;
        }
        if(g_filelists[index].paths[pid].type == PNR_IM_MSGTYPE_SYSPATH)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get user(%d) path(%d) is syspath",index,pid);
            return CFD_FILEACTION_RETURN_NOTARGET;
        }
        if(g_filelists[index].paths[pid].filenum > 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"path(%s) is not null",name);
            return CFD_FILEACTION_RETURN_PATHNOTNULL;
        }
        pnr_filelist_dbdelete_byid(index,g_filelists[index].paths[pid].id);
        memset(&g_filelists[index].paths[pid],0,sizeof(struct cfd_filepath_struct));
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_filelist_init
  Description:  file list 数据初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_filelist_init(void)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn,i,index = 0,id = 0;
    int offset=0;
    char db_file[PNR_FILENAME_MAXLEN+1] = {0};
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_userfilelist_struct* puser = NULL;

    for(index=0;index<PNR_IMUSER_MAXNUM;index++)
    {
        memset(&g_filelists[index],0,sizeof(struct cfd_userfilelist_struct));
        snprintf(db_file,PNR_FILENAME_MAXLEN,"%suser%d/pnrouter_msglog.db",DAEMON_PNR_USERDATA_DIR,index);
        if(access(db_file, F_OK) == OK && gp_localuser[index] != NULL)
        {
            puser = &g_filelists[index];
            //先拉取该用户的所有目录
            //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,timestamp,depens,type,pathid,fname"
                " from cfd_filelist_tbl where type=%d or type=%d;",PNR_IM_MSGTYPE_SYSPATH,PNR_IM_MSGTYPE_USRPATH);
            //DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_filelist_init:sql(%s)",sql_cmd);
            if(sqlite3_get_table(g_msglogdb_handle[index], sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow && i < CFD_PATHS_MAXNUM; i++ )
                {   
                    id = atoi(dbResult[offset+4]);
                    if(id >= 0 && id <= CFD_PATHS_MAXNUM)
                    {
                        puser->paths[id].id = atoi(dbResult[offset]);
                        puser->paths[id].lasttime = atoi(dbResult[offset+1]);
                        puser->paths[id].depens = atoi(dbResult[offset+2]);
                        puser->paths[id].type = atoi(dbResult[offset+3]);
                        puser->paths[id].pathid = id;
                        if(dbResult[offset+5])
                        {
                            strcpy(puser->paths[id].name,dbResult[offset+5]);
                        }
                    }
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"####user(%d:%d) get id(%d) patch(%d:%d:%s)",index,i,id,puser->paths[id].depens,puser->paths[id].type,puser->paths[id].name);
                    offset += nColumn;
                }
                sqlite3_free_table(dbResult);
            }  
            g_filelists[index].exsit = TRUE;
            g_filelists[index].paths_num = i;            
            //再拉取该用户的所有文件
            //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey"
                " from cfd_filelist_tbl where type!=%d and type!=%d and srcfrom != %d;",PNR_IM_MSGTYPE_SYSPATH,PNR_IM_MSGTYPE_USRPATH,PNR_FILE_SRCFROM_BAKADDRBOOK);
            if(sqlite3_get_table(g_msglogdb_handle[index], sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow && i < CFD_FILES_MAXNUM; i++ )
                {   
                    id = atoi(dbResult[offset+9]);
                    if(id >= 0 && id <= CFD_FILES_MAXNUM)
                    {
                        puser->files[id].id = atoi(dbResult[offset]);
                        puser->files[id].timestamp = atoi(dbResult[offset+1]);
                        puser->files[id].info_ver= atoi(dbResult[offset+2]);
                        puser->files[id].depens = atoi(dbResult[offset+3]);
                        puser->files[id].msgid = atoi(dbResult[offset+4]);
                        puser->files[id].type = atoi(dbResult[offset+5]);
                        puser->files[id].srcfrom = atoi(dbResult[offset+6]);
                        puser->files[id].size = atoi(dbResult[offset+7]);
                        puser->files[id].pathid = atoi(dbResult[offset+8]);
                        puser->files[id].fileid = id;
                        puser->files[id].uindex = index;
                        if(dbResult[offset+10])
                        {
                            strcpy(puser->files[id].from,dbResult[offset+10]);
                        }
                        if(dbResult[offset+11])
                        {
                            strcpy(puser->files[id].to,dbResult[offset+11]);
                        }
                        if(dbResult[offset+12])
                        {
                            strcpy(puser->files[id].name,dbResult[offset+12]);
                        }
                        if(dbResult[offset+13])
                        {
                            strcpy(puser->files[id].path,dbResult[offset+13]);
                        }
                        if(dbResult[offset+14])
                        {
                            strcpy(puser->files[id].md5,dbResult[offset+14]);
                        }
                        if(dbResult[offset+15])
                        {
                            strcpy(puser->files[id].finfo,dbResult[offset+15]);
                        }
                        if(dbResult[offset+16])
                        {
                            strcpy(puser->files[id].skey,dbResult[offset+16]);
                        }
                        if(dbResult[offset+17])
                        {
                            strcpy(puser->files[id].dkey,dbResult[offset+17]);
                        }
                        cfd_filelist_count(index,puser->files[id].pathid,TRUE,puser->files[id].size,puser->files[id].timestamp);
                    }
                    offset += nColumn;
                }
                sqlite3_free_table(dbResult);
            }
            if(puser->files_num > 0)
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_filelist_init:user(%d) total files_num(%d)",index,puser->files_num);
                for( i = 0; i < CFD_PATHS_MAXNUM; i++ )
                {
                    if(puser->paths[i].filenum > 0)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_filelist_init:user(%d) path(%d:%s) filenum(%d)",index,i,puser->paths[i].name,puser->paths[i].filenum);
                    }
                }
                for( i = 0; i < nRow && i < CFD_FILES_MAXNUM; i++ )
                {
                    if(puser->files[i].uindex > 0)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_filelist_init:user(%d) file(%d:%d:%s)",index,puser->files[i].fileid,puser->files[i].id,puser->files[i].name);
                    }
                }
            }
            //再拉取该用户的备份通信录
            //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
            snprintf(sql_cmd,SQL_CMD_LEN,"select id,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey"
                " from cfd_filelist_tbl where srcfrom == %d;",PNR_FILE_SRCFROM_BAKADDRBOOK);
            if(sqlite3_get_table(g_msglogdb_handle[index], sql_cmd, &dbResult, &nRow,&nColumn, &errmsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow && i < CFD_FILES_MAXNUM; i++ )
                {   
                    id = atoi(dbResult[offset+9]);
                    if(id >= 0 && id <= CFD_FILES_MAXNUM)
                    {
                        puser->addrbook[id].id = atoi(dbResult[offset]);
                        puser->addrbook[id].timestamp = atoi(dbResult[offset+1]);
                        puser->addrbook[id].info_ver = atoi(dbResult[offset+2]);
                        //puser->addrbook[id].depens = atoi(dbResult[offset+3]);
                        //puser->addrbook[id].msgid = atoi(dbResult[offset+4]);
                        //puser->addrbook[id].type = atoi(dbResult[offset+5]);
                        //puser->addrbook[id].srcfrom = atoi(dbResult[offset+6]);
                        puser->addrbook[id].fsize = atoi(dbResult[offset+7]);
                        //puser->addrbook[id].pathid = atoi(dbResult[offset+8]);
                        //puser->addrbook[id].fileid = id;
                        puser->addrbook[id].uindex = index;
#if 0
                        if(dbResult[offset+10])
                        {
                            strcpy(puser->files[id].from,dbResult[offset+10]);
                        }
                        if(dbResult[offset+11])
                        {
                            strcpy(puser->files[id].to,dbResult[offset+11]);
                        }
#endif
                        if(dbResult[offset+12])
                        {
                            strcpy(puser->addrbook[id].fname,dbResult[offset+12]);
                        }
                        if(dbResult[offset+13])
                        {
                            strcpy(puser->addrbook[id].fpath,dbResult[offset+13]);
                        }
                        if(dbResult[offset+14])
                        {
                            strcpy(puser->addrbook[id].md5,dbResult[offset+14]);
                        }
                        if(dbResult[offset+15])
                        {
                            strcpy(puser->addrbook[id].finfo,dbResult[offset+15]);
                            puser->addrbook[id].addrnum = atoi(puser->addrbook[id].finfo);
                        }
                        if(dbResult[offset+16])
                        {
                            strcpy(puser->addrbook[id].fkey,dbResult[offset+16]);
                        }
                        puser->addrbook_num++;
                    }
                    offset += nColumn;
                }
                sqlite3_free_table(dbResult);
            }
            puser->addrbook_oldest = 0;
            for(i=0;i<puser->addrbook_num;i++)
            {
                if(puser->addrbook[i].timestamp < puser->addrbook[puser->addrbook_oldest].timestamp)
                {
                    puser->addrbook_oldest = i;
                }
            }
        }
    }
    return OK;
}

/**********************************************************************************
  Function:      cfd_rnodedb_init
  Description:  新版rnode db 初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnodedb_init(void)
{
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnodedb_init start(%d)",time(NULL));
    cfd_rnodelist_dbinit();
    cfd_rnode_userinfo_dbinit();
    cfd_rnode_friendsrecord_dbinit();
    cfd_msglogtbl_dbinit();
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_rnodedb_init ok(%d)",time(NULL));
    return OK;
}
/**********************************************************************************
  Function:      cfd_userdata_init
  Description:  新版rnode 用户数据初始化
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_userdata_init(void)
{
    memset(&g_cfdgeninfo,0,sizeof(g_cfdgeninfo));
    cfd_rnodelist_init();
    cfd_oldusermapping_init();
    cfd_userlist_init();
    cfd_activelist_init();
    cfd_friendrecords_init();
    return OK;
}
/**********************************************************************************
  Function:      im_rnodeonline_notice_func
  Description: 节点上线消息广播
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
int im_rnodeonline_noticemsg_create(int msgid,char* retmsg,int* retmsg_len)
{
    int i = 0;
    char tmp_userinfo[CFD_USERONE_INFOMAXLEN+1] = {0};
    char* ret_buff = NULL;

    cJSON *ret_root = cJSON_CreateObject();
    if(ret_root == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        return ERROR;
    }
    cJSON *ret_params = cJSON_CreateObject();
    cJSON *pJsonArry = cJSON_CreateArray();
    cJSON *pJsonsub = NULL;
    if(pJsonArry == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)PNR_API_VERSION_V6));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)msgid++));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_RNODEONLINE_NOTICE));
    cJSON_AddItemToObject(ret_params, "Type", cJSON_CreateNumber(g_pnrdevtype));
    cJSON_AddItemToObject(ret_params, "Weight", cJSON_CreateNumber(g_rlist_node[CFD_RNODE_DEFAULT_RID].weight));
    cJSON_AddItemToObject(ret_params, "Mac", cJSON_CreateString(g_dev_hwaddr));
    cJSON_AddItemToObject(ret_params, "NodeId", cJSON_CreateString(g_rlist_node[CFD_RNODE_DEFAULT_RID].nodeid));
    cJSON_AddItemToObject(ret_params, "RouteId", cJSON_CreateString(g_rlist_node[CFD_RNODE_DEFAULT_RID].routeid));
    cJSON_AddItemToObject(ret_params, "Rname", cJSON_CreateString(g_rlist_node[CFD_RNODE_DEFAULT_RID].rname));
    cJSON_AddItemToObject(ret_params, "UserNum", cJSON_CreateNumber(g_cfdgeninfo.active_user));
    for( i = 0; i < g_cfdgeninfo.active_user; i++ )
    {
        pJsonsub = cJSON_CreateObject();
        if(pJsonsub == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
            cJSON_Delete(ret_root);
            return ERROR;
        }
        cJSON_AddItemToArray(pJsonArry,pJsonsub);
        memset(tmp_userinfo,0,CFD_USERONE_INFOMAXLEN);
        pthread_mutex_lock(&g_activeuser_lock[i]);
        snprintf(tmp_userinfo,CFD_USERONE_INFOMAXLEN,"%d,%d,%d,%s",
            g_activeuser_list[i].id,g_activeuser_list[i].uindex,
            g_activeuser_list[i].active_time,g_activeuser_list[i].uidstr);
        pthread_mutex_unlock(&g_activeuser_lock[i]);
        cJSON_AddStringToObject(pJsonsub,"User",tmp_userinfo);
    }
    cJSON_AddItemToObject(ret_params,"Users", pJsonArry);
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_tox_send_message
  Description:  节点文本消息发送
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_tox_send_message(Tox* ptox,int friend_num,char*pmsg,int msglen,int msgid)
{
    struct tox_msg_send tmsg;
    char sendmsg[1500] = {0};
    int total_datalen = 0,offset = 0;
    if(ptox == NULL || pmsg == NULL)
    {
        return ERROR;
    } 
    if (msglen >= MAX_CRYPTO_DATA_SIZE) 
    {
        //DEBUG_PRINT(DEBUG_LEVEL_NORMAL,"msglen(%d) MAX_CRYPTO_DATA_SIZE(%d)",msglen,MAX_CRYPTO_DATA_SIZE);
        cJSON *RspJson = cJSON_Parse(pmsg);
        if (!RspJson) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse retbuf(%s) err!", pmsg);
            return ERROR;
        }
        cJSON *RspJsonParams = cJSON_GetObjectItem(RspJson, "data");
        if (!RspJsonParams) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse params(%s) err!", pmsg);
            cJSON_Delete(RspJson);
            return ERROR;
        }
        char *RspStrParams = cJSON_PrintUnformatted_noescape(RspJsonParams);
        if (!RspStrParams) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print params(%s) err!", pmsg);
            cJSON_Delete(RspJson);
            return ERROR;
        }
        total_datalen = strlen(RspStrParams);
        //特殊处理，剥离双引号
        if(RspStrParams[0] == '\"')
        {
            RspStrParams[total_datalen-1] = '\0';
            total_datalen -= 2;
            offset = 1;
        }
        memset(&tmsg,0,sizeof(tmsg));
        tmsg.msg = RspStrParams+offset;
        tmsg.msgid = msgid;
        tmsg.friendnum = friend_num;
        tmsg.msglen = total_datalen;
        for(;tmsg.offset < tmsg.msglen;)
        {
            cJSON *JsonFrame = cJSON_Duplicate(RspJson, true);
		    if (!JsonFrame) {
		        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "dup RspJson err!");
				break;
			}
            //去掉原始的data字段
			cJSON_DeleteItemFromObject(JsonFrame, "data");
            //填充新的字段
            strncpy(sendmsg, tmsg.msg+tmsg.offset, MAX_SEND_DATA_SIZE);
        	cJSON_AddNumberToObject(JsonFrame, "offset", tmsg.offset);
            tmsg.offset += MAX_SEND_DATA_SIZE;
            if(tmsg.offset >= tmsg.msglen)
            {
                cJSON_AddNumberToObject(JsonFrame, "more", 0);
            }
            else
            {
                cJSON_AddNumberToObject(JsonFrame, "more", 1);
            }
			cJSON_AddStringToObject(JsonFrame, "data", sendmsg);
			char *RspStrSend = cJSON_PrintUnformatted_noescape(JsonFrame);
			if (!RspStrSend) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print RspJsonSend err!");
				cJSON_Delete(JsonFrame);
				break;
			}
			tox_friend_send_message(ptox,friend_num,TOX_MESSAGE_TYPE_NORMAL,(uint8_t *)RspStrSend, strlen(RspStrSend), NULL);
			cJSON_Delete(JsonFrame);
			free(RspStrSend);
        }
        cJSON_Delete(RspJson);
        free(RspStrParams);
    }
    else
    {
    	tox_friend_send_message(ptox,friend_num,TOX_MESSAGE_TYPE_NORMAL,(uint8_t *)pmsg,msglen,NULL);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_usersend_textmessage
  Description:  用户文本消息发送
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_usersend_textmessage(int mlist_id,struct lws_cache_msg_struct * pmsg)
{
    int rid = 0, ret = 0,to_uid =0,to_index = 0;
    char *ptox_msg = NULL;
    char* pmsg_base64 = NULL;
    int tar_msglen = 0;
    cJSON *ret_root = NULL;
    char to_idstring[CFD_USER_PUBKEYLEN+1] = {0};
    if(pmsg == NULL)
    {
        return ERROR;
    }
    cfd_toxidformatidstr(pmsg->toid,to_idstring);
    cfd_uinfolistgetdbid_byuidstr(to_idstring,&to_uid);
    if(to_uid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get user(%d) to_id(%s) msg(%s)failed",mlist_id,pmsg->toid,pmsg->msg);
        return ERROR;
    }
    rid = g_activeuser_list[to_uid].active_rid;
    to_index = g_activeuser_list[to_uid].uindex;
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_usersend_textmessage:send(%d:%s) cmd(%d) rid(%d)",to_uid,to_idstring,pmsg->type,rid);
    if(rid == CFD_RNODE_DEFAULT_RID)
    {
        //走本地
        if (g_imusr_array.usrnode[to_index].user_online_type == USER_ONLINE_TYPE_LWS
            && g_imusr_array.usrnode[to_index].appactive_flag == PNR_APPACTIVE_STATUS_FRONT) 
        {
            insert_lws_msgnode_ring(to_index, pmsg->msg, pmsg->msglen);
            pmsg->resend++;
            //这里针对消息推送的时候不是本地消息，但是轮询时变成本地消息的情况(这时候消息还在消息发送方的列表中，没办法删除)
            if(mlist_id != to_index)
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_usersend_textmessage:list(%d) touser(%d) changed",mlist_id,to_index);
                pthread_mutex_unlock(&lws_cache_msglock[mlist_id]);
                pnr_msgcache_dbdelete(pmsg->msgid, mlist_id);
                pthread_mutex_lock(&lws_cache_msglock[mlist_id]);
            }
        }
        else//推送通知
        {
            if(g_noticepost_enable == TRUE && pmsg->notice_flag == FALSE)
            {
                pmsg->notice_flag = TRUE;
                switch(pmsg->type)
                {
                    //case PNR_IM_CMDTYPE_ADDFRIENDPUSH:
                    //case PNR_IM_CMDTYPE_ADDFRIENDREPLY:
                    case PNR_IM_CMDTYPE_PUSHMSG:
                    case PNR_IM_CMDTYPE_PUSHFILE:
                    case PNR_IM_CMDTYPE_PUSHFILE_TOX: 
                        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"###user(%d) msg(%d) post_newmsg_notice###",msg->userid,msg->msgid);
                        post_newmsg_notice(g_daemon_tox.user_toxid,g_imusr_array.usrnode[pmsg->userid].user_toxid,
                            PNR_POSTMSG_PAYLOAD,TRUE,pmsg->msgid);                                    
                        break;
                    case PNR_IM_CMDTYPE_GROUPMSGPUSH:
                        pnr_postmsgs_cache_save(pmsg->msgid,g_imusr_array.usrnode[pmsg->userid].user_toxid,&g_group_pushmsgs_cache);
                        break;
                    default:
                        break;
                }
            }
        }
    }
    else if(rid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%d) rid(%d) err",to_uid,rid);
    }
    else //走tox
    {
        ret = tox_friend_get_connection_status(g_daemon_tox.ptox_handle, g_rlist_node[rid].node_fid, NULL);
    	//DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_usersend_textmessage_bytox:rid(%d) node_fid(%d) status(%d)",rid,g_rlist_node[rid].node_fid,ret);
        if (ret == TOX_CONNECTION_TCP || ret == TOX_CONNECTION_UDP) 
        {
            ret_root = cJSON_CreateObject();
            if (!ret_root) 
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_usersend_textmessage err");
                return -1;
            }
            cJSON_AddItemToObject(ret_root, "mtype", cJSON_CreateNumber(CFD_RNODEMSG_TYPE_FORWARD));
            cJSON_AddItemToObject(ret_root, "listid", cJSON_CreateNumber(mlist_id));
            cJSON_AddItemToObject(ret_root, "user", cJSON_CreateString(pmsg->toid));
            cJSON_AddItemToObject(ret_root, "from", cJSON_CreateString(pmsg->fromid));
            cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)pmsg->msgid));
            tar_msglen = 2*(pmsg->msglen);
            pmsg_base64 = malloc(tar_msglen);
            if(pmsg_base64 == NULL)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_usersend_textmessage malloc err");
            }
            memset(pmsg_base64,0,tar_msglen);
            pnr_base64_encode(pmsg->msg,pmsg->msglen,pmsg_base64,&tar_msglen);
            cJSON_AddItemToObject(ret_root, "data", cJSON_CreateString(pmsg_base64));
            //这里消息内容不能做转义，要不然对端收到会出错
            ptox_msg = cJSON_PrintUnformatted_noescape(ret_root);
            cfd_tox_send_message(g_daemon_tox.ptox_handle,g_rlist_node[rid].node_fid,ptox_msg,strlen(ptox_msg),pmsg->msgid);
            pmsg->resend++;
            free(pmsg_base64);
            free(ptox_msg);
            cJSON_Delete(ret_root);
        }   
        else
        {
            if(g_noticepost_enable == TRUE && pmsg->notice_flag == FALSE)
            {
                pmsg->notice_flag = TRUE;
                switch(pmsg->type)
                {
                    //case PNR_IM_CMDTYPE_ADDFRIENDPUSH:
                    //case PNR_IM_CMDTYPE_ADDFRIENDREPLY:
                    case PNR_IM_CMDTYPE_PUSHMSG:
                    case PNR_IM_CMDTYPE_PUSHFILE:
                    case PNR_IM_CMDTYPE_PUSHFILE_TOX: 
                        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"###user(%d) msg(%d) post_newmsg_notice###",msg->userid,msg->msgid);
                        post_newmsg_notice(g_daemon_tox.user_toxid,g_imusr_array.usrnode[pmsg->userid].user_toxid,
                            PNR_POSTMSG_PAYLOAD,TRUE,pmsg->msgid);                                    
                        break;
                    case PNR_IM_CMDTYPE_GROUPMSGPUSH:
                        pnr_postmsgs_cache_save(pmsg->msgid,g_imusr_array.usrnode[pmsg->userid].user_toxid,&g_group_pushmsgs_cache);
                        break;
                    default:
                        break;
                }
            }
        }
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnode_self_detch
  Description:  节点自检是否正常启动
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        OK / ERROR
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_rnode_self_detch(void)
{
    int modify_flag = FALSE,rid =0;
    for(rid=2;rid<CFD_RNODE_MAXNUM;rid++)
    {
        if(strcmp(g_rlist_node[rid].nodeid,g_daemon_tox.user_toxid) == OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"clean repeat rid(%d:%s)",rid,g_daemon_tox.user_toxid);
            memset(&g_rlist_node[rid],0,sizeof(struct cfd_nodeinfo_struct));
            cfd_rnode_dbdelte_byid(rid);
            break;
        }
    }
    if(strcmp(g_rlist_node[CFD_RNODE_DEFAULT_RID].nodeid,g_daemon_tox.user_toxid) != OK)
    {
        memset(g_rlist_node[CFD_RNODE_DEFAULT_RID].nodeid,0,TOX_ID_STR_LEN);
        strcpy(g_rlist_node[CFD_RNODE_DEFAULT_RID].nodeid,g_daemon_tox.user_toxid);
        modify_flag = TRUE;
    }
    if(strcmp(g_rlist_node[CFD_RNODE_DEFAULT_RID].routeid,g_rnode_tox.user_toxid) != OK)
    {
        memset(g_rlist_node[CFD_RNODE_DEFAULT_RID].routeid,0,TOX_ID_STR_LEN);
        strcpy(g_rlist_node[CFD_RNODE_DEFAULT_RID].routeid,g_rnode_tox.user_toxid);
        modify_flag = TRUE;
    }
    if(strcmp(g_rlist_node[CFD_RNODE_DEFAULT_RID].mac,g_dev_hwaddr) != OK)
    {
        memset(g_rlist_node[CFD_RNODE_DEFAULT_RID].mac,0,MACSTR_MAX_LEN);
        strcpy(g_rlist_node[CFD_RNODE_DEFAULT_RID].mac,g_dev_hwaddr);
        modify_flag = TRUE;
    }
    if(strcmp(g_rlist_node[CFD_RNODE_DEFAULT_RID].rname,g_dev_nickname) != OK)
    {
        memset(g_rlist_node[CFD_RNODE_DEFAULT_RID].rname,0,PNR_USERNAME_MAXLEN);
        strcpy(g_rlist_node[CFD_RNODE_DEFAULT_RID].rname,g_dev_nickname);
        modify_flag = TRUE;
    }
    if(modify_flag == TRUE)
    {
        if(g_rlist_node[CFD_RNODE_DEFAULT_RID].id == 0)
        {
            g_rlist_node[CFD_RNODE_DEFAULT_RID].id = CFD_RNODE_DEFAULT_RID;
            g_rlist_node[CFD_RNODE_DEFAULT_RID].type = g_pnrdevtype;
            g_rlist_node[CFD_RNODE_DEFAULT_RID].weight = CFD_RNODE_SELF_WEIGHT;
            cfd_rnodelist_dbinsert(&g_rlist_node[CFD_RNODE_DEFAULT_RID]);
        }
        else
        {
            cfd_rnode_dbupdate_byid(&g_rlist_node[CFD_RNODE_DEFAULT_RID]);
        }
    }
    g_nodeonline_info.type = g_rlist_node[CFD_RNODE_DEFAULT_RID].type;
    g_nodeonline_info.weight = g_rlist_node[CFD_RNODE_DEFAULT_RID].weight;
    strcpy(g_nodeonline_info.mac,g_rlist_node[CFD_RNODE_DEFAULT_RID].mac);
    strcpy(g_nodeonline_info.nodeid,g_rlist_node[CFD_RNODE_DEFAULT_RID].nodeid);
    strcpy(g_nodeonline_info.routeid,g_rlist_node[CFD_RNODE_DEFAULT_RID].routeid);
    strcpy(g_nodeonline_info.rname,g_rlist_node[CFD_RNODE_DEFAULT_RID].rname);
    g_nodeonline_info_ok = TRUE;
    return OK;
}
/**********************************************************************************
  Function:      cfd_rnode_friend_connect
  Description:   节点启动之后自动添加邻居节点好友
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:成功
                 1:失败
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/ 
int cfd_rnode_friend_connect(int node_flag)
{
    int i = 0;
    char node_onlinemsg[CFD_USERONE_INFOMAXLEN+1] = {0};
    
    if(node_flag == CFD_NODE_TOXID_NID)
    {
        snprintf(node_onlinemsg,CFD_USERONE_INFOMAXLEN,"Rnode(%s) Online",g_rlist_node[CFD_RNODE_DEFAULT_RID].nodeid);
        for(i=CFD_RNODE_DEFAULT_RID+1;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(g_rlist_node[i].nodeid[0] != 0 && g_rlist_node[i].node_cstatus != CFD_RID_NODE_CSTATUS_CONNETTED)
            {
                g_rlist_node[i].node_fid = cfd_add_friends_force(node_flag,g_rlist_node[i].nodeid,node_onlinemsg);
                if(g_rlist_node[i].node_fid < 0)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add rnode(%s) failed",g_rlist_node[i].nodeid);
                    g_rlist_node[i].node_cstatus = CFD_RID_NODE_CSTATUS_CONNETERR;
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add rnode(%s) OK",g_rlist_node[i].nodeid);
                    g_rlist_node[i].node_cstatus = CFD_RID_NODE_CSTATUS_CONNETTING;
                }
            }
        }
    }
    else
    {
        for(i=CFD_RNODE_DEFAULT_RID+1;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(g_rlist_node[i].routeid[0] != 0 && g_rlist_node[i].route_cstatus != CFD_RID_NODE_CSTATUS_CONNETTED)
            {
                g_rlist_node[i].route_fid = cfd_add_friends_force(node_flag,g_rlist_node[i].routeid,"HI Route Online");
                if(g_rlist_node[i].route_fid< 0)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add friend(%s) failed",g_rlist_node[i].routeid);
                    g_rlist_node[i].route_cstatus = CFD_RID_NODE_CSTATUS_CONNETERR;
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add friend(%s) OK",g_rlist_node[i].routeid);
                    g_rlist_node[i].route_cstatus = CFD_RID_NODE_CSTATUS_CONNETTING;
                }
            }
        }
    }    
    return OK;
}
/***********************************************************************************
  Function:      cfd_dbfuzzygetid_bymailinfo
  Description:  根据mailinfo模糊查找用户id
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
int cfd_dbfuzzygetid_bymailinfo(char* mailinfo,int* uid)
{
    int8* errMsg = NULL;
    char sql_cmd[SQL_CMD_LEN] = {0};

    if(mailinfo == NULL)
    {
        return ERROR;
    }
    //rnode_uinfo_tab(id integer primary key autoincrement,local,uindex,uinfoseq,friendseq,friendnum,createtime,version,type,capacity,idstring,uname,mailinfo,avatar,atamd5,info);
    snprintf(sql_cmd,SQL_CMD_LEN,"select id from cfd_uinfo_tbl where mailinfo like '%%%s%%';",mailinfo);    
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_dbfuzzygetid_bymailinfo(%s)",sql_cmd);
    if(sqlite3_exec(g_db_handle,sql_cmd,dbget_int_result,uid,&errMsg))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"sql(%s) get cur_status failed",sql_cmd);
        sqlite3_free(errMsg);
        return ERROR;
    }
    return OK;
}
/*****************************************************************************
 函 数 名  : cfd_toxmsgcache_dbinsert
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
int cfd_usertox_textmsgcache_dbinsert(int userid,int msgid, char *fromid, char *toid, int type, 
    char *pmsg, int len, int logid, int ctype,char* sign,char* nonce,char* prikey)
{
    int ret = 0;
	int8 *err = NULL;
	char sql[MSGSQL_CMD_LEN] = {0};
    int sql_len = MSGSQL_CMD_LEN;
    struct lws_cache_msg_struct *msg = NULL;
	struct lws_cache_msg_struct *tmsg = NULL;
    struct lws_cache_msg_struct *n = NULL;
    char *p_sign = "";
    char *p_nonce = "";
    char *p_prikey = "";
    int msg_totallen = 0;
    char* p_sql = NULL;
    if(len <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:len(%d) err",len);
        return ERROR;
    }
    if(pmsg != NULL && strlen(pmsg) > CMD_MAXLEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:malloc failed");
            return ERROR;
        }
        sql_len = MSGSQL_ALLOC_MAXLEN;
    }
    else
    {
        p_sql = sql;
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
		snprintf(p_sql, MSGSQL_CMD_LEN, "select id from msg_tbl where fromid='%s' and logid=%d;",fromid, logid);
		char **dbResult = NULL;
		int nRow = 0, nColumn = 0;
		ret = sqlite3_get_table(g_msgcachedb_handle[userid], sql, &dbResult, &nRow, &nColumn, &err);
		if (ret == SQLITE_OK) {
			if (nRow > 0) {
				DEBUG_PRINT(DEBUG_LEVEL_INFO, "msg exist(fromid:%s--logid:%d)", fromid, logid);
				sqlite3_free_table(dbResult);
                if(sql_len == MSGSQL_ALLOC_MAXLEN)
                {
                    free(p_sql);
                }  
                return OK;
			}
		} else {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sql(%s) err(%s)", sql,err);
			sqlite3_free(err);
            if(sql_len == MSGSQL_ALLOC_MAXLEN)
            {
                free(p_sql);
            }  
            return ERROR;
		}
	}

    //table msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey);
    snprintf(p_sql, sql_len, "insert into msg_tbl "
        "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey)"
        "values(%d,'%s','%s',%d,%d,'%s',%d,'','',0,%d,%d,'%s','%s','%s');",
        msgid,fromid,toid,type,ctype,pmsg,len,logid,PNR_IM_MSGTYPE_TEXT,p_sign, p_nonce, p_prikey);
	//DEBUG_PRINT(DEBUG_LEVEL_INFO, "insert user(%d) sql_cmd(%s)", userid,p_sql);
    if (sqlite3_exec(g_msgcachedb_handle[userid], p_sql, 0, 0, &err)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", p_sql, err);
        sqlite3_free(err);
        if(sql_len == MSGSQL_ALLOC_MAXLEN)
        {
            free(p_sql);
        }  
        return ERROR;
    }
    msg_totallen = sizeof(struct lws_cache_msg_struct) + len + 1;
	msg = (struct lws_cache_msg_struct *)malloc(msg_totallen);
	if (!msg) {
		DEBUG_PRINT(DEBUG_LEVEL_ERROR, "malloc err!");
        if(sql_len == MSGSQL_ALLOC_MAXLEN)
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
    msg->ftype = PNR_IM_MSGTYPE_TEXT;
    msg->filesize = 0;
    msg->logid = logid;
    msg->notice_flag = FALSE;
	strncpy(msg->msg, pmsg, len);
	strncpy(msg->fromid, fromid, TOX_ID_STR_LEN);
    strncpy(msg->toid, toid, TOX_ID_STR_LEN);
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
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"user(%d) list addmsg(%s)",userid,msg->msg);
OUT:
    pthread_mutex_unlock(&lws_cache_msglock[userid]);
    if(sql_len == MSGSQL_ALLOC_MAXLEN)
    {
        free(p_sql);
    }  
    //DEBUG_PRINT(DEBUG_LEVEL_INFO, "inset cache msg(%d:%s) len(%d)", userid, pmsg,len);    
	return OK;
}
/*****************************************************************************
 函 数 名  : cfd_usermsgnode_insert
 功能描述  : 插入数据库消息缓存
 输入参数  : int userid  
             char* from  
             char*to     
             char* pmsg  
             int msglen  
             int limit  重传次数 0表示不限
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月22日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int cfd_usermsgnode_insert(int userid, char *from, char *to,
    char *pmsg, int msglen, int type, int logid, int msgid,char* sign, char* nonce, char* prikey)
{
    int ret = 0;
    int to_id = 0;
    char from_uidstr[CFD_USER_PUBKEYLEN+1] = {0};
    char to_uidstr[CFD_USER_PUBKEYLEN+1] = {0};
    if (userid <=0 || userid > PNR_IMUSER_MAXNUM ||from == NULL || to == NULL || pmsg == NULL) 
    {
        return -1;
    }
    cfd_toxidformatidstr(from,from_uidstr);
    cfd_toxidformatidstr(to,to_uidstr);
    cfd_uinfolistgetdbid_byuidstr(to_uidstr,&to_id);
    if(to_id <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"touser(%s:%s) not found",to,to_uidstr);
        return -1;
    }
    //DEBUG_PRINT(DEBUG_LEVEL_INFO, "add msg cache!msgid(%d)(%s)", msgid,pmsg);
    ret = cfd_usertox_textmsgcache_dbinsert(userid,msgid,from_uidstr,to_uidstr,type,pmsg,msglen,logid,PNR_MSG_CACHE_TYPE_TOX,sign,nonce,prikey);
    return ret;
}
/*****************************************************************************
 函 数 名  : cfd_rnodetox_msgnode_insert
 功能描述  : 插入数据库消息缓存
 输入参数  : int userid  
             char* from  
             char*to     
             char* pmsg  
             int msglen  
             int limit  重传次数 0表示不限
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月22日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int cfd_rnodetox_msgnode_insert(char *from, char *to,int type,int msgid,int msglen,char *pmsg)
{
    char *ptox_msg = NULL;
    int ret = 0;
    char* pmsg_base64 = NULL;
    int msg_len = 0,tar_msglen = 0;
    int8 *err = NULL;
    char sql[MSGSQL_CMD_LEN] = {0};
    int sql_len = MSGSQL_CMD_LEN;
    struct lws_cache_msg_struct *msg = NULL;
    struct lws_cache_msg_struct *tmsg = NULL;
    struct lws_cache_msg_struct *n = NULL;
    int msg_totallen = 0;
    char* p_sql = NULL;
    int to_rid = 0;

    if (from == NULL || to == NULL || pmsg == NULL) 
    {
        return -1;
    }
    to_rid = cfd_rnodelist_getid_bydevid(CFD_NODE_TOXID_NID,to);
    if(to_rid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad to_rid(%s)",to);
        return -1;
    }
	cJSON *ret_root = cJSON_CreateObject();
    if (!ret_root) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_tox_msgnode_insert err");
        return -1;
    }    
    cJSON_AddItemToObject(ret_root, "mtype", cJSON_CreateNumber(CFD_RNODEMSG_TYPE_NODEMSG));
    cJSON_AddItemToObject(ret_root, "user", cJSON_CreateString(from));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)msgid));
    msg_len = strlen(pmsg);
    tar_msglen = 2*msg_len;
    pmsg_base64 = malloc(tar_msglen);
    if(pmsg_base64 == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"insert_tox_msgnode malloc err");
    }
    memset(pmsg_base64,0,2*msg_len);
    pnr_base64_encode(pmsg,msg_len,pmsg_base64,&tar_msglen);
    cJSON_AddItemToObject(ret_root, "data", cJSON_CreateString(pmsg_base64));
    //这里消息内容不能做转义，要不然对端收到会出错
    ptox_msg = cJSON_PrintUnformatted_noescape(ret_root);
    tar_msglen = strlen(ptox_msg);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO, "add tox msg cache!msgid(%d)(%s)", msgid,ptox_msg);
    if(tar_msglen > CMD_MAXLEN)
    {
        p_sql = malloc(MSGSQL_ALLOC_MAXLEN);
        if(p_sql == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"pnr_msgcache_dbinsert:malloc failed");
            return ERROR;
        }
        sql_len = MSGSQL_ALLOC_MAXLEN;
    }
    else
    {
        p_sql = sql;
    }
    //table msg_tbl(id integer primary key autoincrement,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey);
    snprintf(p_sql, sql_len, "insert into msg_tbl "
        "(id,fromid,toid,type,ctype,msg,len,filename,filepath,filesize,logid,ftype,sign,nonce,prikey)"
        "values(%d,'%s','%s',%d,%d,'%s',%d,'','',0,0,%d,'','','');",
        msgid,from,to,type,PNR_MSG_CACHE_TYPE_TOX,ptox_msg,tar_msglen,PNR_IM_MSGTYPE_TEXT);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)", p_sql);
    if (sqlite3_exec(g_msgcachedb_handle[CFD_NODEID_USERINDEX], p_sql, 0, 0, &err)) 
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "sqlite cmd(%s) err(%s)", p_sql, err);
        sqlite3_free(err);
        if(sql_len == MSGSQL_ALLOC_MAXLEN)
        {
            free(p_sql);
        }  
        return ERROR;
    }
    msg_totallen = sizeof(struct lws_cache_msg_struct) + tar_msglen + 1;
    msg = (struct lws_cache_msg_struct *)malloc(msg_totallen);
    if (!msg) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "malloc err!");
        if(sql_len == MSGSQL_ALLOC_MAXLEN)
        {
            free(p_sql);
        } 
        return ERROR;
    }
    memset(msg, 0, msg_totallen);
    INIT_LIST_HEAD(&msg->list);
    msg->userid = CFD_NODEID_USERINDEX;
    msg->msgid = msgid;
    msg->msglen = tar_msglen;
    msg->timestamp = time(NULL);
    msg->type = type;
    msg->ctype = PNR_MSG_CACHE_TYPE_TOX;
    msg->ftype = PNR_IM_MSGTYPE_TEXT;
    msg->filesize = 0;
    msg->logid = to_rid;//这里复用了
    msg->notice_flag = FALSE;
    strncpy(msg->msg, ptox_msg, tar_msglen);
    strncpy(msg->fromid, from, TOX_ID_STR_LEN);
    strncpy(msg->toid, to, TOX_ID_STR_LEN);
    pthread_mutex_lock(&lws_cache_msglock[CFD_NODEID_USERINDEX]);
    if (!list_empty(&g_lws_cache_msglist[CFD_NODEID_USERINDEX].list)) {
        list_for_each_safe(tmsg, n, &g_lws_cache_msglist[CFD_NODEID_USERINDEX].list, struct lws_cache_msg_struct, list) {
            if (tmsg->msgid > msgid) {
                list_add_before(&msg->list, &tmsg->list);
                goto OUT;
            }
        }
    }
    list_add_tail(&msg->list, &g_lws_cache_msglist[CFD_NODEID_USERINDEX].list);
    
OUT:
    pthread_mutex_unlock(&lws_cache_msglock[CFD_NODEID_USERINDEX]);
    if(sql_len == MSGSQL_ALLOC_MAXLEN)
    {
        free(p_sql);
    }  
    free(pmsg_base64);
    free(ptox_msg);
    cJSON_Delete(ret_root);
    return ret;
}
/***********************************************************************************
  Function:      cfd_dbget_friendsall_byindex
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
int cfd_dbget_friendsall_byindex(int index)
{
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    int i = 0,fid = 0,rnode_id = 0;

    if(index <= 0 || index > PNR_IMUSER_MAXNUM)
    {
        return ERROR;
    }
    //rnode_friends_tab(id integer primary key autoincrement,createtime,status,uindex,uid,fid,oneway,uidstr,fidstr,remark,info)
	snprintf(sql_cmd,SQL_CMD_LEN,"select fid,oneway,fidstr,remark from rnode_friends_tab where uindex=%d;",index);
	if(sqlite3_get_table(g_rnodedb_handle, sql_cmd, &dbResult, &nRow, &nColumn, &errmsg) == SQLITE_OK)
    {
        offset = nColumn; //字段值从index开始呀
        for( i = 0; i < nRow ; i++ )
        {
            g_imusr_array.usrnode[index].friends[i].friend_uid = atoi(dbResult[offset]);
            g_imusr_array.usrnode[index].friends[i].oneway = atoi(dbResult[offset+1]);
            if(dbResult[offset+2])
            {
                strncpy(g_imusr_array.usrnode[index].friends[i].user_pubkey,dbResult[offset+2],CFD_USER_PUBKEYLEN);
                strcpy(g_imusr_array.usrnode[index].friends[i].user_toxid,g_imusr_array.usrnode[index].friends[i].user_pubkey);
            }
            if(dbResult[offset+3])
            {
                strncpy(g_imusr_array.usrnode[index].friends[i].user_remarks,dbResult[offset+3],PNR_USERNAME_MAXLEN);
            }
            fid = g_imusr_array.usrnode[index].friends[i].friend_uid;
            if(fid > 0 && fid < CFD_URECORD_MAXNUM)
            {
                strcpy(g_imusr_array.usrnode[index].friends[i].user_nickname,g_ruser_list[fid].uname);
            }
            g_imusr_array.usrnode[index].friends[i].exsit_flag =  TRUE;
            g_imusr_array.usrnode[index].friends[i].online_status = USER_ONLINE_STATUS_OFFLINE;
            rnode_id =  g_activeuser_list[fid].active_rid;
            if(rnode_id > 0 && rnode_id <= CFD_RNODE_MAXNUM)
            {
                g_imusr_array.usrnode[index].friends[i].active_rid = rnode_id;
                strcpy(g_imusr_array.usrnode[index].friends[i].user_devid,g_rlist_node[rnode_id].nodeid);
                strcpy(g_imusr_array.usrnode[index].friends[i].user_devname,g_rlist_node[rnode_id].rname);
                if(rnode_id == CFD_RNODE_DEFAULT_RID)
                {
                    g_imusr_array.usrnode[index].friends[i].local = TRUE;
                }
            }
            offset += nColumn;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"uid(%d) get friend(%d:%s) friend_id(%s) userkey(%s) remarks(%s) dev(%s:%s)",
                index,i,g_imusr_array.usrnode[index].friends[i].user_nickname,g_imusr_array.usrnode[index].friends[i].user_toxid,
                g_imusr_array.usrnode[index].friends[i].user_pubkey,g_imusr_array.usrnode[index].friends[i].user_remarks,
                g_imusr_array.usrnode[index].friends[i].user_devid,g_imusr_array.usrnode[index].friends[i].user_devname);
        }
        //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
        g_imusr_array.usrnode[index].friendnum = i;
        sqlite3_free_table(dbResult);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_getindexbyidstr
  Description:  替换原有的get_indexbyid
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_getindexbyidstr(char* p_id)
{
    int id_len = 0;
    char idstr[CFD_USER_PUBKEYLEN+1] = {0};
    char* p_idstr = NULL;
    
    if(p_id == NULL)
    {
        return -1;
    }
    id_len = strlen(p_id);
    if(id_len == TOX_ID_STR_LEN)
    {
        cfd_olduseridstr_dbgetbytoxid(p_id,idstr);
        p_idstr = idstr;
    }
    else
    {
        p_idstr = p_id;
    }
    return cfd_uinfolistgetindex_byuidstr(p_idstr);
}
/**********************************************************************************
  Function:      cfd_toxidformatidstr
  Description:  toxid映射为idstr
  Calls:
  Called By:
  Input:
  Output:        none
  Return:        0:没找到
                 num:实例id
  Others:

  History: 1. Date:2018-07-30
                  Author:Will.Cao
                  Modification:Initialize
***********************************************************************************/
int cfd_toxidformatidstr(char* p_toxid,char* p_idstr)
{
    int idlen = 0;
    if(p_toxid == NULL || p_idstr == NULL)
    {
        return ERROR;
    }
    idlen = strlen(p_toxid);
    if(idlen == TOX_ID_STR_LEN)
    {
        cfd_olduseridstr_dbgetbytoxid(p_toxid,p_idstr);
    }
    else if(idlen == CFD_USER_PUBKEYLEN)
    {
        strncpy(p_idstr,p_toxid,CFD_USER_PUBKEYLEN);
    }
    else
    {
        return ERROR;
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_nodeonline_notice_send
  Description: 节点上线发送通知
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
int cfd_nodeonline_notice_send(int rid)
{
    int unum = 0,i = 0;
    while(g_nodeonline_info_ok != TRUE)
    {
        usleep(5000);
    }
    pthread_mutex_lock(&g_onlinemsg_lock);
    memset(&g_onlinemsg,0,sizeof(g_onlinemsg));
    memcpy(&g_onlinemsg.head,&g_nodeonline_info,sizeof(struct cfd_node_online_msghead));
    for(i=0;i<CFD_URECORD_MAXNUM;i++)
    {
        if(g_ruser_list[i].index > 0)
        {
            g_onlinemsg.users[unum].uid = i;
            g_onlinemsg.users[unum].index = g_ruser_list[i].index;
            g_onlinemsg.users[unum].friend_seq = g_ruser_list[i].friend_seq;
            g_onlinemsg.users[unum].uinfo_seq = g_ruser_list[i].uinfo_seq;
            pthread_mutex_lock(&g_activeuser_lock[i]);
            g_onlinemsg.users[unum].last_active = g_activeuser_list[i].active_time;
            g_onlinemsg.users[unum].active_rid = g_activeuser_list[i].active_rid;
            pthread_mutex_unlock(&g_activeuser_lock[i]);
            strcpy(g_onlinemsg.users[unum].idstr,g_ruser_list[i].uidstr);
            unum++;
        }
    }
    g_onlinemsg.head.innode_usernum = unum;
    if(rid > 0)
    {
        g_onlinemsg.to_rid = rid;
        im_pushmsg_callback(CFD_NODEID_USERINDEX,PNR_IM_CMDTYPE_RNODEONLINE_NOTICE,FALSE,PNR_API_VERSION_V6,(void *)&g_onlinemsg);
    }
    else
    {
        for(i = 2;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(g_rlist_node[i].id > 0)
            {
                g_onlinemsg.to_rid = i;
                im_pushmsg_callback(CFD_NODEID_USERINDEX,PNR_IM_CMDTYPE_RNODEONLINE_NOTICE,FALSE,PNR_API_VERSION_V6,(void *)&g_onlinemsg);
            }
        }
    }
    pthread_mutex_unlock(&g_onlinemsg_lock);
    return OK;
}
/*****************************************************************************
 函 数 名  : cfd_addfriend_devinfo_byidstr
 功能描述  : 添加好友的设备信息
 输入参数  : char *path  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年10月23日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int cfd_addfriend_devinfo_byidstr(int index,char* friend_uidstr)
{
    int f_id = 0,uid = 0,rid =0;
    struct im_friends_struct* p_friend = NULL;
    if(index <=0 || index > PNR_IMUSER_MAXNUM || friend_uidstr == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_addfriend_devinfo_byidstr:bad index(%d)",index);
        return ERROR;
    }
    cfd_uinfolistgetdbid_byuidstr(friend_uidstr,&uid);
    if(uid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_addfriend_devinfo_byidstr:bad index(%d)",index);
        return ERROR;
    }
    rid = g_activeuser_list[uid].active_rid;
    //更新系统内存中的
    f_id = cfd_getfriendid_byidstr(index,friend_uidstr);
    if(f_id >= 0 && rid > 0)
    {
        p_friend = &g_imusr_array.usrnode[index].friends[f_id];
        if(strcmp(p_friend->user_devid,g_rlist_node[rid].nodeid) != OK)
        {
            memset(p_friend->user_devid,0,TOX_ID_STR_LEN);
            strcpy(p_friend->user_devid,g_rlist_node[rid].nodeid);
        }
        if(strcmp(p_friend->user_devname,g_rlist_node[rid].rname) != OK)
        {
            memset(p_friend->user_devname,0,PNR_USERNAME_MAXLEN);
            strcpy(p_friend->user_devname,g_rlist_node[rid].rname);
        }
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"cfd_addfriend_devinfo_byidstr:get user(%d) f_id(%d) dev(%s:%s)",
            index,f_id,p_friend->user_devid,p_friend->user_devname);
    }
    return OK;
}
/**********************************************************************************
  Function:      cfd_userlogin_deal
  Description: IM模块用户登陆命令解析处理
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
int cfd_userlogin_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char router_id[TOX_ID_STR_LEN+1] = {0};
    char sign[PNR_AES_CBC_KEYSIZE+1] = {0};
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    char* ret_buff = NULL;
    int need_asysn = 0;
    int index =0,uid = -1;
    char nickname[PNR_USERNAME_MAXLEN +1] = {0};
    char user_sn[PNR_USN_MAXLEN+1] = {0};
    char uid_str[CFD_USER_PUBKEYLEN+1] = {0};
    char user_toxid[TOX_ID_STR_LEN+1] = {0};
    if(params == NULL)
    {
        return ERROR;
    }

    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"RouteId",router_id,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserSn",user_sn,PNR_USN_MAXLEN);    
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",user_toxid,TOX_ID_STR_LEN);
    //CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"DataFileVersion",data_version,PNR_IDCODE_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Sign",sign,PNR_AES_CBC_KEYSIZE);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"NickName",nickname,PNR_USERNAME_MAXLEN);
    //rid检查
    if(strncmp(router_id,g_daemon_tox.user_toxid,TOX_ID_STR_LEN) != OK)
    {
        ret_code = PNR_LOGIN_RETCODE_BAD_RID;
    }
    else if(strlen(sign) == 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userlogin_deal:bad input sign");
        ret_code = PNR_LOGIN_RETCODE_BAD_LOGINKEY;
    }
    else
    {
        ret_code = cfd_toxidformatidstr(user_toxid,uid_str);
        if(ret_code != OK)
        {
            ret_code = PNR_LOGIN_RETCODE_BAD_UID;
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userlogin_deal:bad input sign");
        }
        else
        {
            //sign 验证
            if(pnr_sign_check(sign,strlen(sign),uid_str,TRUE) != OK)
            {
                ret_code = PNR_LOGIN_RETCODE_BAD_LOGINKEY;
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userlogin_deal:input sign(%s) usrkey(%s) check failed",sign,uid_str);
            }
            cfd_uinfolistgetdbid_byuidstr(uid_str,&uid);
            if(uid <= 0)
            {
                ret_code = PNR_LOGIN_RETCODE_BAD_UID;
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_userlogin_deal:input usrkey(%s) check failed",uid_str);
            }
            else
            {
                index = g_ruser_list[uid].index;
                if(index <= 0 || index > PNR_IMUSER_MAXNUM)
                {
                }
                //检查并更新nickname
                else if((strlen(nickname) > 0) && (strcmp(nickname,g_ruser_list[uid].uname) != OK))
                {
                    g_ruser_list[uid].uinfo_seq++;
                    memset(g_ruser_list[uid].uname,0,PNR_USERNAME_MAXLEN);
                    strcpy(g_ruser_list[uid].uname,nickname);
                    cfd_uinfouname_dbupdate_byindex(uid,g_ruser_list[uid].uinfo_seq,nickname);
                }
            }
        }           
    }
    //成功登陆
    if(ret_code == PNR_USER_LOGIN_OK)
    {
        if(g_msglogdb_handle[index] == NULL)
        {
             if (cfdsql_msglogdb_init(index) != OK) 
             {
                 DEBUG_PRINT(DEBUG_LEVEL_ERROR, "[%d]init msglog db failed",index);
             }
        }
        if(g_msgcachedb_handle[index] == NULL)
        {
             if (sql_msgcachedb_init(index) != OK) 
             {
                 DEBUG_PRINT(DEBUG_LEVEL_ERROR, "[%d]init msgcache db failed",index);
             }
        }
        //检测是否已经有用户登陆了，如果是，需要向之前用户推送消息
        if(g_imusr_array.usrnode[index].user_onlinestatus == USER_ONLINE_STATUS_ONLINE)
        {
            pnr_relogin_push(index,head->iftox,head->friendnum,head->pss);    
        }
        imuser_friendstatus_push(index,USER_ONLINE_STATUS_ONLINE);
        imuser_frienduinfo_sysch(uid);
        cfd_uactive_lastactive_update_byid(uid,(int)time(NULL),CFD_RNODE_DEFAULT_RID);
        pnr_account_dbupdate_lastactive_bytoxid(g_imusr_array.usrnode[index].user_toxid);
        g_imusr_array.usrnode[index].appactive_flag = PNR_APPACTIVE_STATUS_FRONT;
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d-%s) online", index,g_imusr_array.usrnode[index].user_toxid);
    }
    //构建响应消息
    cJSON * ret_root = cJSON_CreateObject();
    cJSON * ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_LOGIN));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "Routerid", cJSON_CreateString(router_id));
    cJSON_AddItemToObject(ret_params, "RouterName", cJSON_CreateString(g_dev_nickname));
    cJSON_AddItemToObject(ret_params, "UserSn", cJSON_CreateString(user_sn));
    cJSON_AddItemToObject(ret_params, "UserId", cJSON_CreateString(uid_str));
    cJSON_AddItemToObject(ret_params, "NeedAsysn", cJSON_CreateNumber(need_asysn));
    if(ret_code == PNR_USER_LOGIN_OK)
    {
        cJSON_AddItemToObject(ret_params, "NickName", cJSON_CreateString(nickname));
        cJSON_AddItemToObject(ret_params, "AdminId", cJSON_CreateString(g_imusr_array.usrnode[PNR_ADMINUSER_PSN_INDEX].user_toxid));
        cJSON_AddItemToObject(ret_params, "AdminName", cJSON_CreateString(g_imusr_array.usrnode[PNR_ADMINUSER_PSN_INDEX].user_nickname));
        cJSON_AddItemToObject(ret_params, "AdminKey", cJSON_CreateString(g_imusr_array.usrnode[PNR_ADMINUSER_PSN_INDEX].user_pubkey));
    }
    else
    {
        cJSON_AddItemToObject(ret_params, "NickName", cJSON_CreateString(""));
    }

    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_group_pulllist_deal
  Description: IM模块拉取自己的群组列表解析处理
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
int cfd_group_pulllist_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = PNR_GROUPPULL_RETCODE_OK;
    char* ret_buff = NULL;
    char userid[TOX_ID_STR_LEN+1] = {0};
    char rid[TOX_ID_STR_LEN+1] = {0};
    char startid[TOX_ID_STR_LEN+1] = {0};
    int i = 0,num = 0,gid = -1,tmp_gid = -1;
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn;
    char sql_cmd[SQL_CMD_LEN] = {0};
    char uid_str[CFD_USER_PUBKEYLEN+1] = {0};
    int offset=0,uindex= 0,uid_len = 0;
    char* p_idstr = NULL;
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",userid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"RouterId",rid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"TargetNum",num,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"StartId",startid,TOX_ID_STR_LEN);

    //参数检查
    uid_len = strlen(userid);
    if(uid_len == TOX_ID_STR_LEN)
    {
        cfd_olduseridstr_getbytoxid(userid,uid_str);
        p_idstr = uid_str;
    }
    else if(uid_len == CFD_USER_PUBKEYLEN)
    {
        p_idstr = userid;
    }
    uindex = cfd_uinfolistgetindex_byuidstr(p_idstr);
    if(uindex < 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_group_pulllist_deal:bad uid(%s)",userid);
        ret_code = PNR_GROUPPULL_RETCODE_ERR;
    }
    else if(num > 0)
    {
        gid = get_gidbygrouphid(startid);
        if(gid < 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_group_pulllist_deal:bad startid(%s)",startid);
            ret_code = PNR_GROUPPULL_RETCODE_ERR;
        }
    }
    
    cJSON *ret_root = cJSON_CreateObject();
    if(ret_root == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        return ERROR;
    }
    cJSON *ret_params = cJSON_CreateObject();
    cJSON *pJsonArry = cJSON_CreateArray();
    cJSON *pJsonsub = NULL;
    if(pJsonArry == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_GROUPLISTPULL));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(userid));
    if(ret_code == PNR_GROUPPULL_RETCODE_OK)
    {
        if(*plws_index == 0)
        {
            *plws_index = uindex;
        }
        if(num == 0)
        {
            //groupuser_tbl(gid,uid,uindex,type,initmsgid,lastmsgid,timestamp,utoxid,uname,uremark,gremark,pubkey)
            snprintf(sql_cmd, SQL_CMD_LEN, "select gid,gremark,pubkey from groupuser_tbl where uindex=%d;",uindex);
        }
        else
        {
            snprintf(sql_cmd, SQL_CMD_LEN, "select gid,gremark,pubkey from groupuser_tbl where uindex=%d and gid > %d order by gid desc limit %d;",
                uindex,gid,num);
        }
        if(sqlite3_get_table(g_groupdb_handle, sql_cmd, &dbResult, &nRow, 
            &nColumn, &errmsg) == SQLITE_OK)
        {
            offset = nColumn; //字段值从offset开始呀
            for( i = 0; i < nRow ; i++ )
            {
                pJsonsub = cJSON_CreateObject();
                if(pJsonsub == NULL)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
                    cJSON_Delete(ret_root);
                    return ERROR;
                }
                cJSON_AddItemToArray(pJsonArry,pJsonsub);
                tmp_gid = atoi(dbResult[offset]);
                if(tmp_gid >=0 && tmp_gid < PNR_GROUP_MAXNUM)
                {
                    cJSON_AddStringToObject(pJsonsub,"GId",g_grouplist[tmp_gid].group_hid);
                    cJSON_AddNumberToObject(pJsonsub,"Verify",g_grouplist[tmp_gid].verify);
                    cJSON_AddStringToObject(pJsonsub,"GName",g_grouplist[tmp_gid].group_name);
                    cJSON_AddStringToObject(pJsonsub,"GAdmin",g_grouplist[tmp_gid].owner);
                    if(dbResult[offset+1] != NULL)
                    {
                        cJSON_AddStringToObject(pJsonsub,"Remark",dbResult[offset+1]);
                    }
                    else
                    {
                        cJSON_AddStringToObject(pJsonsub,"Remark","");
                    }
                    if(dbResult[offset+2] != NULL)
                    {
                        cJSON_AddStringToObject(pJsonsub,"UserKey",dbResult[offset+2]);
                    }
                    else
                    {
                        cJSON_AddStringToObject(pJsonsub,"UserKey","");
                    }
                }
                offset += nColumn;
            }
            sqlite3_free_table(dbResult);
        }
        cJSON_AddItemToObject(ret_params, "GroupNum", cJSON_CreateNumber(nRow));
        cJSON_AddItemToObject(ret_params,"Payload", pJsonArry);
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_updata_avatar_deal
  Description:  用户更新指定用户头像
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
int cfd_updata_avatar_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    char* ret_buff = NULL;
    char from[PNR_FILEPATH_MAXLEN+1] = {0};
    char to[PNR_FILEPATH_MAXLEN+1] = {0};
    char fullname[PNR_FILEPATH_MAXLEN+1] = {0};
    char filename[PNR_FILENAME_MAXLEN+1] = {0};
    char md5string[PNR_MD5_VALUE_MAXLEN+1] = {0};
    int fromid = 0,toid = 0,uid = -1;
    int filesize = FALSE;
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Uid",from,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Fid",to,PNR_FILENAME_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Md5",md5string,PNR_MD5_VALUE_MAXLEN);
    //参数检查

    fromid = cfd_getindexbyidstr(from);
    toid = cfd_getindexbyidstr(to);
    if(fromid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_updata_avatar_deal input uid err(%s)",from);
        ret_code = PNR_UPDATE_AVATAR_RETCODE_BADUID;
    }
    else if(toid <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_updata_avatar_deal input fid err(%s)",to);
        ret_code = PNR_UPDATE_AVATAR_RETCODE_BADUID;
    }
    else
    {
        if(*plws_index == 0)
        {
            *plws_index = fromid;
        }
        //获取系统当前的头像信息
        if(gp_localuser[toid] == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_updata_avatar_deal user(%s) avatar no exsit",to);
            ret_code = PNR_UPDATE_AVATAR_RETCODE_FILE_NOEXSIT; 
        }
        else
        {
            uid = gp_localuser[toid]->id;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"im_updata_avatar_deal get user(%d:%s),avatar(%s:) md(%s) uname(%s)",
                toid,g_ruser_list[uid].uidstr,g_ruser_list[uid].avatar,g_ruser_list[uid].md5,g_ruser_list[uid].uname);
            //检测目标文件是否存在
            snprintf(filename,PNR_FILENAME_MAXLEN,"/%s%s",PNR_AVATAR_DIR,g_ruser_list[uid].avatar);
            snprintf(fullname,PNR_FILEPATH_MAXLEN,"%s%s",PNR_AVATAR_FULLDIR,g_ruser_list[uid].avatar);
            if(access(fullname,F_OK) != OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_updata_avatar_deal user(%s) avatar no exsit",to);
                ret_code = PNR_UPDATE_AVATAR_RETCODE_FILE_NOEXSIT; 
            }
            else if(strncasecmp(md5string,g_ruser_list[uid].md5,PNR_MD5_VALUE_MAXLEN) == OK)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_updata_avatar_deal user(%s) md5(%s) same",to,md5string);
                ret_code = PNR_UPDATE_AVATAR_RETCODE_NOCHANGE; 
                filesize = im_get_file_size(fullname);
            }
            else
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"input md5(%s),db md5(%s)",md5string,g_ruser_list[uid].md5);
                filesize = im_get_file_size(fullname);
                if(filesize <= 0)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_updata_avatar_deal user avatar(%s) fillsize err",fullname);
                    ret_code = PNR_UPDATE_AVATAR_RETCODE_FILE_NOEXSIT; 
                }
                else
                {
                    ret_code = PNR_UPDATE_AVATAR_RETCODE_OK; 
                }
            }
        }
    }
    //构建响应消息
    cJSON * ret_root =  cJSON_CreateObject();
    cJSON * ret_params =  cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_UPDATEAVATAR));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(from));
    if(ret_code == PNR_UPDATE_AVATAR_RETCODE_OK || ret_code == PNR_UPDATE_AVATAR_RETCODE_NOCHANGE)
    {
        cJSON_AddItemToObject(ret_params, "FileSize", cJSON_CreateNumber(filesize));
        cJSON_AddItemToObject(ret_params, "FileName", cJSON_CreateString(filename));
        cJSON_AddItemToObject(ret_params, "FileMD5", cJSON_CreateString(g_ruser_list[uid].md5));
        cJSON_AddItemToObject(ret_params, "TargetKey", cJSON_CreateString(g_ruser_list[uid].uidstr));
    }
    cJSON_AddItemToObject(ret_params, "TargetId", cJSON_CreateString(to));
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_pullmsg_cmd_deal
  Description: IM模块拉取聊天信息消息处理
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
int cfd_pullmsg_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    struct im_sendmsg_msgstruct* pmsg = NULL;
    struct im_sendmsg_msgstruct* ptmp_msg = NULL;
    int msgnum = 0;
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    char* ret_buff = NULL;
    int index = 0,i = 0,src_msgid= 0;
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    char fileinfo[PNR_FILEINFO_MAXLEN+1] = {0};
    char filemd5[PNR_MD5_VALUE_MAXLEN+1] = {0};
    char filepath[PNR_FILEPATH_MAXLEN+1] = {0};
    char from_idstr[CFD_USER_PUBKEYLEN+1] = {0};
    char to_idstr[CFD_USER_PUBKEYLEN+1] = {0};
    char* ptmp = NULL;
    int fileinfo_len =0,fromid_len = 0,toid_len = 0;
    char* pfrom = NULL;
    char* pto = NULL;

    if(params == NULL)
    {
        return ERROR;
    }
    pmsg = (struct im_sendmsg_msgstruct *)calloc(1, sizeof(*pmsg));
    if (!pmsg) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err");
        return ERROR;
    }
    ptmp_msg = (struct im_sendmsg_msgstruct *)calloc(1, sizeof(*ptmp_msg));
    if (!ptmp_msg) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err2");
        free(pmsg);
        return ERROR;
    }

    //解析参数
    memset(pmsg,0,sizeof(struct im_sendmsg_msgstruct));
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",pmsg->fromuser_toxid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"FriendId",pmsg->touser_toxid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"MsgType",pmsg->msgtype,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"MsgStartId",pmsg->log_id,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"MsgNum",msgnum,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"SrcMsgId",src_msgid,TOX_ID_STR_LEN);
    //useid 处理
    if(msgnum <= 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad msgnum(%s)",msgnum);
        ret_code = PNR_MSGSEND_RETCODE_FAILED;
    }
    else
    {
        fromid_len = strlen(pmsg->fromuser_toxid);
        if(fromid_len == TOX_ID_STR_LEN)
        {
            cfd_olduseridstr_dbgetbytoxid(pmsg->fromuser_toxid,from_idstr);
            pfrom = from_idstr;
        }
        else
        {
            pfrom = pmsg->fromuser_toxid;
        }
        toid_len = strlen(pmsg->touser_toxid);
        if(toid_len == TOX_ID_STR_LEN)
        {
            cfd_olduseridstr_dbgetbytoxid(pmsg->touser_toxid,to_idstr);
            pto = to_idstr;
        }
        else
        {
            pto = pmsg->touser_toxid;
        }
        //查询是否已经存在的实例
        index = cfd_uinfolistgetindex_byuidstr(pfrom);
        if(index == 0)
        {
            ret_code = PNR_MSGSEND_RETCODE_FAILED;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"get UserId(%s) failed",pfrom);
        }
        else
        {
            ret_code = PNR_MSGSEND_RETCODE_OK;
            if(*plws_index == 0)
            {
                *plws_index = index;
            }
        }
    }
    
    //构建响应消息
    cJSON *ret_root = cJSON_CreateObject();
    if(ret_root == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        free(pmsg);
        free(ptmp_msg);
        return ERROR;
    }
    cJSON *ret_params = cJSON_CreateObject();
    cJSON *pJsonArry = cJSON_CreateArray();
    cJSON *pJsonsub = NULL;
    if(pJsonArry == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        free(pmsg);
        free(ptmp_msg);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)(head->api_version)));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
	cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_PULLMSG));
    cJSON_AddItemToObject(ret_params, "UserId", cJSON_CreateString(pmsg->fromuser_toxid));
    cJSON_AddItemToObject(ret_params, "FriendId", cJSON_CreateString(pmsg->touser_toxid));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));

    if(ret_code == PNR_MSGSEND_RETCODE_OK && index != 0)
    {
        if(msgnum > PNR_IMCMD_PULLMSG_MAXNUM)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"msgmun(%d) outof maxnum(%d)",msgnum,PNR_IMCMD_PULLMSG_MAXNUM);
            msgnum = PNR_IMCMD_PULLMSG_MAXNUM;
        }
        if(pmsg->log_id == 0)
        {
             snprintf(sql_cmd, SQL_CMD_LEN, "select * from(select id,logid,timestamp,status,"
				"from_user,to_user,msg,msgtype,filepath,filesize,sign,nonce,prikey,id from cfd_msglog_tbl where "
				"userindex=%d and ((from_user='%s' and to_user='%s') or "
				"(from_user='%s' and to_user='%s')) and msgtype not in (%d,%d) "
				"order by id desc limit %d)temp order by id;",
                index, pfrom, pto,pto, pfrom,
                PNR_IM_MSGTYPE_SYSTEM, PNR_IM_MSGTYPE_AVATAR, msgnum);
        }
        else
        {
            snprintf(sql_cmd, SQL_CMD_LEN, "select * from(select id,logid,timestamp,status,"
				"from_user,to_user,msg,msgtype,filepath,filesize,sign,nonce,prikey,id from cfd_msglog_tbl where "
				"userindex=%d and id<%d and ((from_user='%s' and to_user='%s') or "
                "(from_user='%s' and to_user='%s')) and msgtype not in (%d,%d) "
                "order by id desc limit %d)temp order by id;",
                index,pmsg->log_id, pfrom, pto,pto, pfrom,
                PNR_IM_MSGTYPE_SYSTEM, PNR_IM_MSGTYPE_AVATAR, msgnum);
        }

        DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
        if(sqlite3_get_table(g_msglogdb_handle[index], sql_cmd, &dbResult, &nRow, 
            &nColumn, &errmsg) == SQLITE_OK)
        {
            offset = nColumn; //字段值从offset开始呀
            for( i = 0; i < nRow ; i++ )
            {				
                memset(ptmp_msg,0,sizeof(struct im_sendmsg_msgstruct));
                ptmp_msg->db_id = atoi(dbResult[offset++]);
                ptmp_msg->log_id = atoi(dbResult[offset++]);
                ptmp_msg->timestamp = atoi(dbResult[offset++]);
                ptmp_msg->msg_status = atoi(dbResult[offset++]);
                snprintf(ptmp_msg->fromuser_toxid,TOX_ID_STR_LEN+1,"%s",dbResult[offset++]);
                snprintf(ptmp_msg->touser_toxid,TOX_ID_STR_LEN+1,"%s",dbResult[offset++]);
                snprintf(ptmp_msg->msg_buff,IM_MSG_PAYLOAD_MAXLEN,"%s",dbResult[offset++]);
				ptmp_msg->msgtype = atoi(dbResult[offset++]);
				snprintf(ptmp_msg->ext,IM_MSG_MAXLEN,"%s",dbResult[offset++]);
                ptmp_msg->ext2 = atoi(dbResult[offset++]);
                snprintf(ptmp_msg->sign,PNR_RSA_KEY_MAXLEN,"%s",dbResult[offset++]);
                snprintf(ptmp_msg->nonce,PNR_RSA_KEY_MAXLEN,"%s",dbResult[offset++]);
                snprintf(ptmp_msg->prikey,PNR_RSA_KEY_MAXLEN,"%s",dbResult[offset++]);
                //跳过id值
				offset ++;
                pJsonsub = cJSON_CreateObject();
                if(pJsonsub == NULL)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
                    cJSON_Delete(ret_root);
                    return ERROR;
                }
                cJSON_AddItemToArray(pJsonArry,pJsonsub); 
                cJSON_AddNumberToObject(pJsonsub,"MsgId",ptmp_msg->db_id); 
                //cJSON_AddNumberToObject(pJsonsub,"DbId",ptmp_msg->db_id); 
                cJSON_AddNumberToObject(pJsonsub,"MsgType",ptmp_msg->msgtype); 
                cJSON_AddNumberToObject(pJsonsub,"TimeStamp",ptmp_msg->timestamp); 
                cJSON_AddNumberToObject(pJsonsub,"Status",ptmp_msg->msg_status); 
                if(strcmp(ptmp_msg->fromuser_toxid,pfrom) == OK)
                {
                    cJSON_AddNumberToObject(pJsonsub,"Sender",USER_MSG_SENDER_SELF);
                }
                else
                {
                    cJSON_AddNumberToObject(pJsonsub,"Sender",USER_MSG_RECIVEVE_SELF);
                }
                cJSON_AddStringToObject(pJsonsub,"Nonce",ptmp_msg->nonce);
                cJSON_AddStringToObject(pJsonsub,"Sign",ptmp_msg->sign);
                cJSON_AddStringToObject(pJsonsub,"PriKey",ptmp_msg->prikey);           
				/* need to return filepath */
				switch (ptmp_msg->msgtype) 
                {
    				case PNR_IM_MSGTYPE_FILE:
    				case PNR_IM_MSGTYPE_IMAGE:
    				case PNR_IM_MSGTYPE_AUDIO:
    				case PNR_IM_MSGTYPE_MEDIA:
    					cJSON_AddStringToObject(pJsonsub, "FileName", ptmp_msg->msg_buff);
                        ptmp = strchr(ptmp_msg->ext,PNR_FILEINFO_ATTACH_FLAG);
                        if(ptmp != NULL)
                        {
                            fileinfo_len = ptmp_msg->ext+strlen(ptmp_msg->ext)-ptmp;
                            fileinfo_len = ((fileinfo_len >= PNR_FILEINFO_MAXLEN)?PNR_FILEINFO_MAXLEN:fileinfo_len);
                            memset(fileinfo,0,PNR_FILEINFO_MAXLEN);
                            strncpy(fileinfo,ptmp,fileinfo_len);
                            //DEBUG_PRINT(DEBUG_LEVEL_INFO,"####get ext(%s) fileinfo(%s)",tmp_msg.ext,fileinfo);
                            ptmp[0] = 0;
                            cJSON_AddStringToObject(pJsonsub, "FileInfo", fileinfo+1);
                        }
                        if(strncmp(ptmp_msg->ext,WS_SERVER_INDEX_FILEPATH,strlen(WS_SERVER_INDEX_FILEPATH)) == OK)
                        {
                            cJSON_AddStringToObject(pJsonsub, "FilePath", ptmp_msg->ext+strlen(WS_SERVER_INDEX_FILEPATH));
                            md5_hash_file(ptmp_msg->ext, filemd5);
                            cJSON_AddStringToObject(pJsonsub, "FileMD5", filemd5);
                        }
                        else
                        {
                            snprintf(filepath,PNR_FILEPATH_MAXLEN,"%s/%s",WS_SERVER_INDEX_FILEPATH,ptmp_msg->ext);
                            md5_hash_file(filepath, filemd5);
                            cJSON_AddStringToObject(pJsonsub, "FileMD5", filemd5);
                            cJSON_AddStringToObject(pJsonsub, "FilePath", ptmp_msg->ext);
                        }
                        cJSON_AddNumberToObject(pJsonsub, "FileSize", ptmp_msg->ext2);
    					break;

    				default:
    					cJSON_AddStringToObject(pJsonsub, "Msg", ptmp_msg->msg_buff);
                        if(ptmp_msg->ext2)
                        {
                            cJSON_AddNumberToObject(pJsonsub,"AssocId",ptmp_msg->ext2); 
                        }
				}
                /*DEBUG_PRINT(DEBUG_LEVEL_INFO,"im_pullmsg_cmd_deal:id(%d) logid(%d)(%s->%s) Msg(%s)",
                    i,tmp_msg.log_id,tmp_msg.fromuser_toxid,tmp_msg.touser_toxid,tmp_msg.msg_buff);*/
            }
            //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get nRow(%d) nColumn(%d)",nRow,nColumn);
            msgnum = i;
            sqlite3_free_table(dbResult);
        }
        cJSON_AddItemToObject(ret_params, "MsgNum", cJSON_CreateNumber(msgnum));
        if(src_msgid)
        {
            cJSON_AddItemToObject(ret_params, "SrcMsgId", cJSON_CreateNumber(src_msgid));
        }
        cJSON_AddItemToObject(ret_params,"Payload", pJsonArry);
    }
    else
    {
        cJSON_AddItemToObject(ret_params, "MsgNum", cJSON_CreateNumber(0));
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    free(pmsg);
    free(ptmp_msg);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < VERSION_MAXLEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}

/**********************************************************************************
  Function:      cfd_pullfriend_cmd_deal
  Description: IM模块拉取好友信息消息处理
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
int cfd_pullfriend_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char user_toxid[TOX_ID_STR_LEN+1] = {0};
    char id_str[CFD_USER_PUBKEYLEN+1] = {0};
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    char* ret_buff = NULL;
    int index = 0,i = 0,id_len = 0,fid = 0,rid = 0;
    char* pidstr = NULL;
    if(params == NULL)
    {
        return ERROR;
    }

    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",user_toxid,TOX_ID_STR_LEN);

    //useid 处理
    id_len = strlen(user_toxid);
    if(id_len == TOX_ID_STR_LEN)
    {
        cfd_olduseridstr_getbytoxid(user_toxid,id_str);
        pidstr = id_str;
    }
    else
    {
        pidstr = user_toxid;
    }
    //查询是否已经存在的实例
    index = cfd_uinfolistgetindex_byuidstr(pidstr);
    if(index == 0)
    {
        ret_code = PNR_MSGSEND_RETCODE_FAILED;
        DEBUG_PRINT(DEBUG_LEVEL_INFO,"get UserId(%s) failed",pidstr);
    }
    else
    {
        ret_code = PNR_MSGSEND_RETCODE_OK;
        if(*plws_index == 0)
        {
            *plws_index = index;
        }
    }
    
    //构建响应消息
    cJSON * ret_root =  cJSON_CreateObject();
    if(ret_root == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        return ERROR;
    }
    cJSON *ret_params = cJSON_CreateObject();
    cJSON *pJsonArry = cJSON_CreateArray();
    cJSON *pJsonsub = NULL;
    if(pJsonArry == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)(head->api_version)));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
	cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_PULLFRIEDN));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    if(ret_code == PNR_MSGSEND_RETCODE_OK && index != 0
        && g_imusr_array.usrnode[index].friendnum > 0)
    {
        pthread_mutex_lock(&(g_user_friendlock[index]));
        cJSON_AddItemToObject(ret_params, "FriendNum", cJSON_CreateNumber(g_imusr_array.usrnode[index].friendnum));
        cJSON_AddItemToObject(ret_params,"Payload", pJsonArry);
        for(i=0;i<PNR_IMUSER_FRIENDS_MAXNUM;i++)
        {
            if(g_imusr_array.usrnode[index].friends[i].exsit_flag)
            {
                pJsonsub = cJSON_CreateObject();
                if(pJsonsub == NULL)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
                    cJSON_Delete(ret_root);
                    pthread_mutex_unlock(&(g_user_friendlock[index]));
                    return ERROR;
                }
           		cJSON_AddItemToArray(pJsonArry,pJsonsub); 
#if 0//暂时不用
        		cJSON_AddStringToObject(pJsonsub,"Index", g_imusr_array.usrnode[index].friends[i].u_hashstr);
#endif
                cJSON_AddStringToObject(pJsonsub,"Name", g_imusr_array.usrnode[index].friends[i].user_nickname);
        		cJSON_AddStringToObject(pJsonsub,"Remarks", g_imusr_array.usrnode[index].friends[i].user_remarks);
        		cJSON_AddStringToObject(pJsonsub,"Id", g_imusr_array.usrnode[index].friends[i].user_toxid);
        		cJSON_AddStringToObject(pJsonsub,"UserKey", g_imusr_array.usrnode[index].friends[i].user_pubkey);
        		cJSON_AddNumberToObject(pJsonsub,"Status",g_imusr_array.usrnode[index].friends[i].online_status); 
        		//cJSON_AddStringToObject(pJsonsub,"RouteName", g_imusr_array.usrnode[index].friends[i].user_devname);
                fid = g_imusr_array.usrnode[index].friends[i].friend_uid;
                if(fid > 0 && fid <= CFD_RNODE_MAXNUM)
                {
                    rid = g_activeuser_list[fid].active_rid;
                    if(rid > 0)
                    {
                        cJSON_AddStringToObject(pJsonsub,"RouteId",g_rlist_node[rid].nodeid);
                        cJSON_AddStringToObject(pJsonsub,"RouteName", g_rlist_node[rid].rname);
                    }
                    cJSON_AddStringToObject(pJsonsub,"Mails", g_ruser_list[fid].mailinfo);
                    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get friend(%d:%s) rid(%d:%s)",fid,g_ruser_list[fid].uidstr,rid,g_rlist_node[rid].rname);
                }
                /*DEBUG_PRINT(DEBUG_LEVEL_INFO,"get friend(%d:%s:%s:%s:%s)",
                        i,g_imusr_array.usrnode[index].friends[i].user_nickname,
                        g_imusr_array.usrnode[index].friends[i].user_remarks,
                        g_imusr_array.usrnode[index].friends[i].user_toxid,
                        g_imusr_array.usrnode[index].friends[i].user_devname);*/
            }
        }
        pthread_mutex_unlock(&(g_user_friendlock[index]));
    }
    else
    {
        cJSON_AddItemToObject(ret_params, "FriendNum", cJSON_CreateNumber(0));
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < VERSION_MAXLEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_user_register_deal
  Description: IM模块Register消息解析处理
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
int cfd_user_register_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char router_id[TOX_ID_STR_LEN+1] = {0};
    char sign[PNR_AES_CBC_KEYSIZE+1] = {0};
    struct pnr_account_struct account;
    struct pnr_account_struct src_account;
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = PNR_REGISTER_RETCODE_OK;
    char* ret_buff = NULL;
    int index = 0,uid = -1;
    int temp_user_flag = FALSE;
    if(params == NULL)
    {
        return ERROR;
    }

    //解析参数
    memset(&account,0,sizeof(account));
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"RouteId",router_id,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserSn",account.user_sn,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"NickName",account.nickname,PNR_USERNAME_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Sign",sign,PNR_AES_CBC_KEYSIZE);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Pubkey",account.user_pubkey,PNR_USER_PUBKEY_MAXLEN);
    //rid检查
    if(strncmp(router_id,g_daemon_tox.user_toxid,TOX_ID_STR_LEN) != OK)
    {
        ret_code = PNR_REGISTER_RETCODE_BADRID;
    }
    else if(strlen(sign) == 0 || strlen(account.user_pubkey) == 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad input");
        ret_code = PNR_REGISTER_RETCODE_OTHERS;
    }
    else if(pnr_account_dbcheck_bypubkey(&account) == ERROR)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user exsit");
        ret_code = PNR_REGISTER_RETCODE_USED;
    }
    else
    {
        //临时用户
        if(strcmp(account.user_sn,g_account_array.temp_user_sn) == OK)
        {
            temp_user_flag = TRUE;
            if(g_imusr_array.cur_user_num >= g_imusr_array.max_user_num)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_user_register_deal: user(%d:%d) over",
                    g_imusr_array.cur_user_num,g_imusr_array.max_user_num);
                ret_code = PNR_REGISTER_RETCODE_OTHERS;
            }
            account.capacity = g_imusr_array.default_user_capacity;
        }
        else
        {
            memset(&src_account,0,sizeof(src_account));
            strcpy(src_account.user_sn,account.user_sn);
            //根据usn获取当前数据库中的账号信息
            pnr_account_get_byusn(&src_account);
            if(src_account.type < PNR_USER_TYPE_ADMIN || src_account.type >= PNR_USER_TYPE_BUTT)
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"user(%s) bad type(%d)",src_account.user_sn,src_account.type);
                ret_code = PNR_REGISTER_RETCODE_OTHERS;
            }
            else if(src_account.active == TRUE)
            {
                ret_code = PNR_REGISTER_RETCODE_USED;
            }
            account.capacity = src_account.capacity;
        }
        if(ret_code == PNR_REGISTER_RETCODE_OK)
        {
            //如果当前还有可分配新用户
            if(g_imusr_array.cur_user_num < g_imusr_array.max_user_num)
            {
                for(index=1;index<=g_imusr_array.max_user_num;index++)
                {
                    if(g_imusr_array.usrnode[index].user_toxid[0] == 0)
                    {   
                        break;
                    }
                }
                //验证pubkey
                if(index <= g_imusr_array.max_user_num)
                {
                    pthread_mutex_lock(&g_pnruser_lock[index]);
                    *plws_index = index;
                    ret_code = PNR_REGISTER_RETCODE_OK;
                    account.active = TRUE;
                    account.index = index;
                    pnr_account_gettype_byusn(account.user_sn,&account.type);
                    strcpy(g_imusr_array.usrnode[index].user_toxid,account.user_pubkey);
                    strcpy(account.toxid,g_imusr_array.usrnode[index].user_toxid);
                    if(temp_user_flag == TRUE)
                    {
                        strcpy(account.mnemonic,PNR_TEMPUSER_MNEMONIC);
                        pnr_account_tmpuser_dbinsert(&account);
                    }
                    else
                    {
                        strcpy(account.mnemonic,src_account.mnemonic);
                        pnr_account_dbupdate(&account);
                    }
                    //注册激活的时候记录一下
                    //pnr_logcache_dbinsert(PNR_IM_CMDTYPE_REGISTER,account.toxid,account.toxid,PNR_CMDTYPE_MSG_REGISTER##account.nickname,PNR_CMDTYPE_EXT_SUCCESS);
                    strcpy(g_imusr_array.usrnode[index].user_nickname,account.nickname);
                    strcpy(g_imusr_array.usrnode[index].user_pubkey,account.user_pubkey);
                    g_imusr_array.cur_user_num++;
                    //注册激活uinfo记录
                    cfd_uinfolistgetdbid_byuidstr(account.user_pubkey,&uid);
                    if(uid <= 0)
                    {
                        //新增一条记录
                        uid = cfd_uinfolist_getidleid();
                        if(uid> 0 && uid<= CFD_URECORD_MAXNUM)
                        {
                            cfd_uinfonode_addnew(uid,index,TRUE,account.type,account.capacity,account.user_pubkey,account.nickname,NULL,NULL,NULL);
                            cfd_uactive_addnew(uid,index,CFD_RNODE_DEFAULT_RID,account.user_pubkey);
                        }
                        else
                        {
                            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_uinfolist_getidleid failed");
                        }
                    }
                    else
                    {
                        //修改当前记录
                        g_ruser_list[uid].id = uid;
                        g_ruser_list[uid].type = account.type;
                        g_ruser_list[uid].index = index;
                        g_ruser_list[uid].local = TRUE;
                        g_ruser_list[uid].createtime = (int)time(NULL);
                        g_ruser_list[uid].capacity = account.capacity;
                        strncpy(g_ruser_list[uid].uname,account.nickname,PNR_USERNAME_MAXLEN);                    
                        strncpy(g_ruser_list[uid].uidstr,account.user_pubkey,CFD_USER_PUBKEYLEN);
                        g_ruser_list[uid].version = DEFAULT_UINFO_VERSION;
                        g_ruser_list[uid].uinfo_seq = DEFAULT_UINFO_VERSION;
                        g_ruser_list[uid].friend_seq = DEFAULT_UINFO_VERSION;
                        cfd_uinfo_dbupdate_byuid(&g_ruser_list[uid]);
                        cfd_uactive_lastactive_update_byid(uid,(int)time(NULL),CFD_RNODE_DEFAULT_RID);
                    }
                    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"register:set uid(%d) index(%d) addr(%p)",uid,index,&g_ruser_list[uid]);
                    //新用户注册激活对应数据库句柄
                    if(g_msglogdb_handle[index] == NULL)
                    {
                    	if (cfdsql_msglogdb_init(index) != OK) 
                        {
                        	DEBUG_PRINT(DEBUG_LEVEL_ERROR, "[%d]init msglog db failed",index);
                        }
                    }
                    if(g_msgcachedb_handle[index] == NULL)
                    {
                        if (sql_msgcachedb_init(index) != OK) 
                        {
                        	DEBUG_PRINT(DEBUG_LEVEL_ERROR, "[%d]init msgcache db failed",index);
                        }
                    }         
                    pthread_mutex_unlock(&g_pnruser_lock[index]);
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get idle index failed");
                    ret_code = PNR_REGISTER_RETCODE_OTHERS;
                }
            }
            else
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"im_user_register_deal: user(%d:%d) over",
                g_imusr_array.cur_user_num,g_imusr_array.max_user_num);
                ret_code = PNR_REGISTER_RETCODE_OTHERS;
            }
        }        
    }
    //成功注册
    if(ret_code == PNR_USER_LOGIN_OK)
    {
        imuser_friendstatus_push(index,USER_ONLINE_STATUS_ONLINE);
        pnr_account_dbupdate_lastactive_bytoxid(g_imusr_array.usrnode[index].user_toxid);
        //自动添加admin用户为好友
        if(strcmp(account.user_sn,g_account_array.account[PNR_ADMINUSER_PSN_INDEX].user_sn) != OK)
        {
            if(g_account_array.admin_user_index == 0)
            {
                memset(&src_account,0,sizeof(src_account));
                strcpy(src_account.user_sn,g_account_array.account[PNR_ADMINUSER_PSN_INDEX].user_sn);
                pnr_account_get_byusn(&src_account);
                if(src_account.active == TRUE && src_account.index > 0)
                {
                    g_account_array.admin_user_index = src_account.index;
                }
            }
            if(g_account_array.admin_user_index > 0)
            {
                pnr_autoadd_localfriend(index,g_account_array.admin_user_index,&account);
            }
        }
        //pnr_sysmsg_push_newuser(account.toxid,account.nickname,account.user_pubkey);
        g_imusr_array.usrnode[index].appactive_flag = PNR_APPACTIVE_STATUS_FRONT;
        DEBUG_PRINT(DEBUG_LEVEL_INFO, "user(%d-%s) register online", index, 
            g_imusr_array.usrnode[index].user_toxid);
    }

    //构建响应消息
	cJSON * ret_root =  cJSON_CreateObject();
    cJSON * ret_params =  cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_REGISTER));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "RouteId", cJSON_CreateString(router_id));
    cJSON_AddItemToObject(ret_params, "RouterName", cJSON_CreateString(g_dev_nickname));
    cJSON_AddItemToObject(ret_params, "UserSn", cJSON_CreateString(account.user_sn));
    if(ret_code == PNR_REGISTER_RETCODE_OK)
    {
        //暂时不用
      /*if(head->api_version == PNR_API_VERSION_V3)
        {
            pnr_uidhash_get(index,0,g_imusr_array.usrnode[index].user_toxid,
                &g_imusr_array.usrnode[index].hashid,g_imusr_array.usrnode[index].u_hashstr);
            cJSON_AddItemToObject(ret_params, "Index", cJSON_CreateString(g_imusr_array.usrnode[index].u_hashstr));
        }*/
        cJSON_AddItemToObject(ret_params, "UserId", cJSON_CreateString(account.toxid));
        cJSON_AddItemToObject(ret_params, "DataFileVersion", cJSON_CreateNumber(ret_code));
        cJSON_AddItemToObject(ret_params, "DataFilePay", cJSON_CreateString(account.toxid));
        pnr_account_dbupdate_lastactive_bytoxid(account.toxid);
    }

    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_replaymsg_deal
  Description: IM模块replay消息解析处理
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
int cfd_replaymsg_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret = 0;
    char toid[TOX_ID_STR_LEN+1] = {0};
    char idstr[CFD_USER_PUBKEYLEN+1] = {0};
    int index = 0,idstr_len = 0;
    char* p_idstr = NULL;

    if(params == NULL)
    {
        return ERROR;
    }
    if(head->im_cmdtype >= PNR_IM_CMDTYPE_UINFOKEY_SYSCH && head->im_cmdtype <= PNR_IM_CMDTYPE_SYSMSGPUSH)
    {
        pnr_msgcache_dbdelete(head->msgid, index);
    }
    else
    {
        CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff, "ToId", toid, TOX_ID_STR_LEN);
        idstr_len = strlen(toid);
        if(idstr_len == TOX_ID_STR_LEN)
        {
            cfd_olduseridstr_getbytoxid(toid,idstr);
            p_idstr = idstr;
        }
        else
        {
            p_idstr = toid;
        }
        index = cfd_uinfolistgetindex_byuidstr(p_idstr);
        if (index == 0) {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR, "get toid(%s) index err", toid);
            return ERROR;
        }
    	pnr_msgcache_dbdelete(head->msgid, index);
        switch(head->im_cmdtype)
        {
            //case PNR_IM_CMDTYPE_ADDFRIENDPUSH:
            case PNR_IM_CMDTYPE_PUSHMSG:
            case PNR_IM_CMDTYPE_PUSHFILE:
            case PNR_IM_CMDTYPE_PUSHFILE_TOX:
            case PNR_IM_CMDTYPE_GROUPMSGPUSH:
                CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Retcode",ret,0);
#if 0//现在不在这里作消息推送
                if(g_imusr_array.usrnode[index].appactive_flag == PNR_APPACTIVE_STATUS_BACKEND)
                {
                    post_newmsg_notice(g_daemon_tox.user_toxid,toid,PNR_POSTMSG_PAYLOAD,TRUE); 
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"###user(%d:%s)  post_newmsg_notice###",index,toid);
                }
#endif
                break;  
            case PNR_IM_CMDTYPE_ADDFRIENDPUSH:
            case PNR_IM_CMDTYPE_ADDFRIENDREPLY:
            case PNR_IM_CMDTYPE_ONLINESTATUSPUSH:
            case PNR_IM_CMDTYPE_DELMSGPUSH:
            case PNR_IM_CMDTYPE_DELFRIENDPUSH:
            case PNR_IM_CMDTYPE_READMSGPUSH:
            case PNR_IM_CMDTYPE_USERINFOPUSH:
            case PNR_IM_CMDTYPE_GROUPINVITEPUSH:
            case PNR_IM_CMDTYPE_VERIFYGROUPPUSH:
            case PNR_IM_CMDTYPE_GROUPSYSPUSH:
            case PNR_IM_CMDTYPE_SYSMSGPUSH:
            //case PNR_IM_CMDTYPE_GROUPMSGPUSH:
                CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Retcode",ret,0);
                break;  
            default:
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad cmd(%d) failed",head->im_cmdtype);
                return ERROR;
        }
    }
    DEBUG_PRINT(DEBUG_LEVEL_INFO,"rec msg(%d) ret(%d)",head->im_cmdtype,ret);
    return OK;
}
/**********************************************************************************
  Function:      cfd_sendmsg_cmd_deal
  Description: IM模块发送消息命令版本解析处理
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
int cfd_sendmsg_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    struct im_sendmsg_msgstruct *msg;
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    char* ret_buff = NULL;
    int index = 0,fid = 0,target_associd = 0;
	cJSON *ret_root = NULL;
    cJSON *ret_params = NULL;
    if (!params) {
        return ERROR;
    }
    msg = (struct im_sendmsg_msgstruct *)calloc(1, sizeof(*msg));
    if (!msg) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err");
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"From",msg->fromuser_toxid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"To",msg->touser_toxid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Msg",msg->msg_buff,IM_MSG_PAYLOAD_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Sign",msg->sign,PNR_RSA_KEY_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Nonce",msg->nonce,PNR_RSA_KEY_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"PriKey",msg->prikey,PNR_RSA_KEY_MAXLEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"AssocId",msg->ext2,TOX_ID_STR_LEN);
    msg->msgtype = PNR_IM_MSGTYPE_TEXT;

    cfd_toxidformatidstr(msg->fromuser_toxid,msg->fromuser);
    cfd_toxidformatidstr(msg->touser_toxid,msg->touser);
   
    if(strcmp(msg->fromuser,msg->touser) == OK)
    {
       DEBUG_PRINT(DEBUG_LEVEL_ERROR,"userid repeat(%s->%s)",
            msg->fromuser_toxid,msg->touser_toxid); 
       ret_code = PNR_MSGSEND_RETCODE_FAILED;
    }
    else if(strlen(msg->msg_buff) > IM_MSG_PAYLOAD_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"msg too long(%d)",strlen(msg->msg_buff)); 
        ret_code = PNR_MSGSEND_RETCODE_FAILED;  
    }
    else
    {
        //查询是否已经存在的实例
        index = cfd_uinfolistgetindex_byuidstr(msg->fromuser);
        if(index == 0)
        {
            //清除对应记录
            ret_code = PNR_MSGSEND_RETCODE_FAILED;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"get fromuser_toxid(%s) failed",msg->fromuser_toxid);
        }
        else
        {
            if(*plws_index == 0)
            {
                *plws_index = index;
            }

			if (!if_friend_available(index, msg->touser)) {
				ret_code = PNR_MSGSEND_RETCODE_NOT_FRIEND;
				goto OUT;
			}
			if (pnr_checkrepeat_bymsgid(index, head->msgid,&(head->repeat_flag)) == TRUE) {
				ret_code = PNR_MSGSEND_RETCODE_OK;
				goto OUT;
			}
            pnr_msglog_getid(index, &msg->log_id);
            pnr_msglog_dbupdate_v3(index,msg->msgtype,msg->log_id,MSG_STATUS_SENDOK,msg->fromuser,
                msg->touser,msg->msg_buff,msg->sign,msg->nonce,msg->prikey,NULL,msg->ext2);

            ret_code = PNR_MSGSEND_RETCODE_OK;
			head->forward = TRUE;
            //这里需要重新做一个映射转换
            if(msg->ext2)
            {
                pnr_msglog_dbget_logid_byid(index,msg->ext2,&target_associd);
                if(target_associd)
                {
                    msg->ext2 = target_associd;
                }
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"replace associd(%d)",msg->ext2);
            }

            if (head->iftox) {
                head->toxmsg = msg;
                head->im_cmdtype = PNR_IM_CMDTYPE_PUSHMSG;
                head->to_userid = cfd_uinfolistgetindex_byuidstr(msg->touser);
            } else {
                cfd_uinfolistgetdbid_byuidstr(msg->touser,&fid);
                //DEBUG_PRINT(DEBUG_LEVEL_INFO,"####send msg get toid(%s) rid(%d)",msg->touser_toxid,fid);
                if(fid > 0)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"get fid(%d) index(%d) uidstr(%s) active_rid(%d)",fid,g_activeuser_list[fid].uindex,g_activeuser_list[fid].uidstr,g_activeuser_list[fid].active_rid);
                    if(g_activeuser_list[fid].active_rid == CFD_RNODE_DEFAULT_RID)
                    {
                        im_pushmsg_callback(g_activeuser_list[fid].uindex,PNR_IM_CMDTYPE_PUSHMSG,TRUE,head->api_version,(void *)msg);
                    }
                    else
                    {
                        im_pushmsg_callback(index,PNR_IM_CMDTYPE_PUSHMSG,FALSE,head->api_version,(void *)msg);
                    }
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_sendmsg_cmd_deal: get fid(%s) failed",msg->touser_toxid);
                }
            }
        }
    }

OUT:
    //构建响应消息
	ret_root = cJSON_CreateObject();
    ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        goto ERR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)(head->api_version)));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_SENDMSG));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "MsgId", cJSON_CreateNumber(msg->log_id));
#if 0
    cJSON_AddItemToObject(ret_params, "From", cJSON_CreateString(msg->from_uid));
    cJSON_AddItemToObject(ret_params, "To", cJSON_CreateString(msg->to_uid));
#else
    cJSON_AddItemToObject(ret_params, "From", cJSON_CreateString(msg->fromuser_toxid));
    cJSON_AddItemToObject(ret_params, "To", cJSON_CreateString(msg->touser_toxid));
#endif
    cJSON_AddItemToObject(ret_params, "Msg", cJSON_CreateString(msg->msg_buff));
    cJSON_AddItemToObject(ret_params, "Nonce", cJSON_CreateString(msg->nonce));
    cJSON_AddItemToObject(ret_params, "PriKey", cJSON_CreateString(msg->prikey));
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    if(head->repeat_flag == TRUE)
    {
        cJSON_AddItemToObject(ret_params, "Repeat", cJSON_CreateNumber(TRUE));
    }

    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        goto ERR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);

    if (!head->iftox || !head->forward)
        free(msg);
    
    return OK;

ERR:
    if (!head->iftox || !head->forward)
        free(msg);
    
    return ERROR;
}
/**********************************************************************************
  Function:      cfd_readmsg_cmd_deal
  Description: IM模块已阅通知消息解析处理
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
int cfd_readmsg_cmd_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    struct im_sendmsg_msgstruct *msg;
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    char* ret_buff = NULL;
    int index = 0,fid=0;
    char tmp_msgbuff[IM_MSG_MAXLEN+1] = {0};
    if (!params) {
        return ERROR;
    }

    msg = (struct im_sendmsg_msgstruct *)calloc(1, sizeof(*msg));
    if (!msg) {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "calloc err");
        return ERROR;
    }

    head->forward = TRUE;

    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",msg->fromuser_toxid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"FriendId",msg->touser_toxid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"ReadMsgs",tmp_msgbuff,IM_MSG_MAXLEN);
    msg->msgtype = PNR_IM_MSGTYPE_SYSTEM;

    //useid 处理
    cfd_toxidformatidstr(msg->fromuser_toxid,msg->fromuser);
    cfd_toxidformatidstr(msg->touser_toxid,msg->touser);
    if(strcmp(msg->fromuser,msg->touser) == OK)
    {
       DEBUG_PRINT(DEBUG_LEVEL_ERROR,"userid repeat(%s->%s)",msg->fromuser_toxid,msg->touser_toxid); 
       ret_code = PNR_MSGSEND_RETCODE_FAILED;
    }
    else if(strlen(tmp_msgbuff) > IM_MSG_PAYLOAD_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"msg too long(%d)",strlen(msg->msg_buff)); 
        ret_code = PNR_MSGSEND_RETCODE_FAILED;  
    }
    else
    {
        //查询是否已经存在的实例
        index = cfd_uinfolistgetindex_byuidstr(msg->fromuser);
        if(index == 0)
        {
            //清除对应记录
            ret_code = PNR_MSGSEND_RETCODE_FAILED;
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"get fromuser_toxid(%s) failed",msg->fromuser);
        }
        else
        {
            if(*plws_index == 0)
            {
                *plws_index = index;
            }
            pnr_readmsg_predeal(index,tmp_msgbuff,msg->msg_buff);
            ret_code = PNR_USER_ADDFRIEND_RETOK;
            if (head->iftox) {
                head->toxmsg = msg;
                head->im_cmdtype = PNR_IM_CMDTYPE_READMSGPUSH;
                head->to_userid = cfd_uinfolistgetindex_byuidstr(msg->touser);
            } else {
                cfd_uinfolistgetdbid_byuidstr(msg->touser,&fid);
                if(fid > 0)
                {
                    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get fid(%d) index(%d) uidstr(%s) active_rid(%d)",fid,g_activeuser_list[fid].uindex,g_activeuser_list[fid].uidstr,g_activeuser_list[fid].active_rid);
                    if(g_activeuser_list[fid].active_rid == CFD_RNODE_DEFAULT_RID)
                    {
                        im_pushmsg_callback(g_activeuser_list[fid].uindex,PNR_IM_CMDTYPE_READMSGPUSH,TRUE,head->api_version,(void *)msg);
                    }
                    else
                    {
                        im_pushmsg_callback(index,PNR_IM_CMDTYPE_READMSGPUSH,FALSE,head->api_version,(void *)msg);
                    }
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfdcfd_readmsg_cmd_deal_sendmsg_cmd_deal: get fid(%s) failed",msg->touser);
                }
            }
        }
    }
    
    //构建响应消息
    cJSON *ret_root = cJSON_CreateObject();
    cJSON *ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        goto ERR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)(head->api_version)));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));

    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_READMSG));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "MsgId", cJSON_CreateString(msg->msg_buff));

    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d)",*retmsg_len);
        free(ret_buff);
        goto ERR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);

    if (!head->iftox)
        free(msg);
    
    return OK;

ERR:
    if (!head->iftox)
        free(msg);
    
    return ERROR;
}
/**********************************************************************************
  Function:      cfd_pullfilepaths_deal
  Description: IM模块拉取文件目录
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
int cfd_pullfilepaths_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0,type = 0;
    char* ret_buff = NULL;
    char userid[TOX_ID_STR_LEN+1] = {0};
    int i = 0,uindex= 0,num = 0;
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",userid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Type",type,0);

    //参数检查
    uindex = cfd_getindexbyidstr(userid);
    if(uindex < 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_pullfilepaths_deal:bad uid(%s)",userid);
        ret_code = PNR_NORMAL_CMDRETURN_BADPARAMS;
    }
    else
    {
        ret_code = PNR_NORMAL_CMDRETURN_OK;
    }

    //构建响应消息
    cJSON * ret_root = cJSON_CreateObject();
    if(ret_root == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON * ret_params = cJSON_CreateObject();
    cJSON *pJsonArry = cJSON_CreateArray();
    cJSON *pJsonsub = NULL;
    if(pJsonArry == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)(head->api_version)));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
	cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_FILEPATHSPULL));
	cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(userid));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    if(g_filelists[uindex].exsit == TRUE)
    {
        cJSON_AddItemToObject(ret_params,"Payload", pJsonArry);
        for(i=0;i<CFD_PATHS_MAXNUM;i++)
        {
            //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get user(%d) type(%d:%d:%d",uindex,i,g_filelists[uindex].paths[i].type,g_filelists[uindex].paths[i].depens);
            if((g_filelists[uindex].paths[i].type == PNR_IM_MSGTYPE_SYSPATH || g_filelists[uindex].paths[i].type == PNR_IM_MSGTYPE_USRPATH)
                && g_filelists[uindex].paths[i].depens == type)
            {
                num ++;
                pJsonsub = cJSON_CreateObject();
                if(pJsonsub == NULL)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
                    cJSON_Delete(ret_root);
                    return ERROR;
                }
           		cJSON_AddItemToArray(pJsonArry,pJsonsub); 
        		cJSON_AddNumberToObject(pJsonsub,"Id",g_filelists[uindex].paths[i].pathid);
                cJSON_AddStringToObject(pJsonsub,"PathName", g_filelists[uindex].paths[i].name);
        		cJSON_AddNumberToObject(pJsonsub,"FilesNum",g_filelists[uindex].paths[i].filenum);
        		cJSON_AddNumberToObject(pJsonsub,"Size",g_filelists[uindex].paths[i].size);
        		cJSON_AddNumberToObject(pJsonsub,"LastModify",g_filelists[uindex].paths[i].lasttime);
                /*DEBUG_PRINT(DEBUG_LEVEL_INFO,"get friend(%d:%s:%s:%s:%s)",
                        i,g_imusr_array.usrnode[index].friends[i].user_nickname,
                        g_imusr_array.usrnode[index].friends[i].user_remarks,
                        g_imusr_array.usrnode[index].friends[i].user_toxid,
                        g_imusr_array.usrnode[index].friends[i].user_devname);*/
            }
        }
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    cJSON_AddItemToObject(ret_params, "Num", cJSON_CreateNumber(num));
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_pullfileslist_deal
  Description: IM模块拉取指定目录文件列表
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
int cfd_pullfileslist_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0,depens = 0,pathid = 0,sort = 0,startid = 0;
    char* ret_buff = NULL;
    char userid[TOX_ID_STR_LEN+1] = {0};
    char pname[PNR_FILENAME_MAXLEN+1] = {0};
    int i = 0,uindex= 0,num = 0,getnum = 0;
    char **dbResult; 
    char *errmsg;
    int nRow, nColumn;
    int offset=0;
    char sql_cmd[SQL_CMD_LEN] = {0};
    struct cfd_fileinfo_struct tmpfile;
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",userid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Depens",depens,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"PathId",pathid,0);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"PathName",pname,PNR_FILENAME_MAXLEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Sort",sort,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"StartId",startid,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Num",num,0);
    //参数检查
    uindex = cfd_getindexbyidstr(userid);
    if(uindex < 0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_pullfileslist_deal:bad uid(%s)",userid);
        ret_code = PNR_NORMAL_CMDRETURN_BADPARAMS;
    }
    else if(pathid <=0 || (pathid > CFD_PATHS_MAXNUM && pathid != CFD_BADADDRBOOK_DEFAULTPATHID) || depens <=0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_pullfileslist_deal:bad pathid(%d)",pathid);
        ret_code = PNR_NORMAL_CMDRETURN_BADPARAMS;
    }
    else
    {
        if(pathid <= CFD_PATHS_MAXNUM && strcmp(g_filelists[uindex].paths[pathid].name,pname) != OK)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_pullfileslist_deal:bad pathid(%d) pname(%s:%s)",pathid,pname,g_filelists[uindex].paths[pathid].name);
            ret_code = PNR_NORMAL_CMDRETURN_BADPARAMS;
        }
    }

    //构建响应消息
    cJSON * ret_root = cJSON_CreateObject();
    cJSON * ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)(head->api_version)));
	cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
	cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_FILESLISTPULL));
	cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(userid));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    if(ret_code == OK)
    {
        cJSON_AddItemToObject(ret_params, "PathId", cJSON_CreateNumber(pathid));
        cJSON_AddItemToObject(ret_params, "PathName", cJSON_CreateString(pname));
        cJSON *pJsonArry = cJSON_CreateArray();
        cJSON *pJsonsub = NULL;
        if(pJsonArry == NULL)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
            cJSON_Delete(ret_root);
            return ERROR;
        }
        cJSON_AddItemToObject(ret_params,"Payload", pJsonArry);
        if(g_filelists[uindex].paths[pathid].filenum > 0)
        {
            
           //cfd_filelist_tbl(id integer primary key autoincrement,userindex,timestamp,version,depens,msgid,type,srcfrom,size,pathid,fileid,fromid,toid,fname,fpath,md5,fileinfo,skey,dkey)
            snprintf(sql_cmd, SQL_CMD_LEN, "select * from(select id,timestamp,version,depens,type,size,pathid,fileid,"
                    "fname,fpath,md5,fileinfo,skey from cfd_filelist_tbl where pathid=%d and type!=%d and type!=%d ",
                    pathid,PNR_IM_MSGTYPE_SYSPATH,PNR_IM_MSGTYPE_USRPATH);
            if(startid > 0)
            {
                memset(pname,0,PNR_FILENAME_MAXLEN);
                snprintf(pname,PNR_FILENAME_MAXLEN,"id<%d ",startid);
                strcat(sql_cmd,pname);
            }
            switch(sort)
            {
                case CFD_FILELIST_SORT_BYTIMEASCE:
                    strcat(sql_cmd,"order by timestamp ");
                    break;

                case CFD_FILELIST_SORT_BYSIZEDESC:
                    strcat(sql_cmd,"order by size desc ");
                    break;
                case CFD_FILELIST_SORT_BYSIZEASCE:
                    strcat(sql_cmd,"order by size ");
                    break;
                case CFD_FILELIST_SORT_BYTIMEDESC:
                default:
                    strcat(sql_cmd,"order by timestamp desc ");
                    break;
            }
            if(num > 0)
            {
                memset(pname,0,PNR_FILENAME_MAXLEN);
                snprintf(pname,PNR_FILENAME_MAXLEN,"limit %d",num);
                strcat(sql_cmd,pname);
            }
            strcat(sql_cmd,")temp order by id;");
            DEBUG_PRINT(DEBUG_LEVEL_INFO, "sql_cmd(%s)",sql_cmd);
            if(sqlite3_get_table(g_msglogdb_handle[uindex], sql_cmd, &dbResult, &nRow, &nColumn, &errmsg) == SQLITE_OK)
            {
                offset = nColumn; //字段值从offset开始呀
                for( i = 0; i < nRow ; i++ )
                {  
                    getnum++;
                    memset(&tmpfile,0,sizeof(struct cfd_fileinfo_struct));
                    //select id,timestamp,version,depens,type,size,pathid,fname,fpath,md5,fileinfo,skey 
                    tmpfile.id = atoi(dbResult[offset]);
                    tmpfile.timestamp = atoi(dbResult[offset+1]);
                    tmpfile.info_ver = atoi(dbResult[offset+2]);
                    tmpfile.depens = atoi(dbResult[offset+3]);
                    tmpfile.type = atoi(dbResult[offset+4]);
                    tmpfile.size = atoi(dbResult[offset+5]);
                    tmpfile.pathid = atoi(dbResult[offset+6]);
                    tmpfile.fileid = atoi(dbResult[offset+7]);
                    if(dbResult[offset+8])
                    {
                        strcpy(tmpfile.name,dbResult[offset+8]);
                    }
                    if(dbResult[offset+9])
                    {
                        strcpy(tmpfile.path,dbResult[offset+9]);
                    }
                    if(dbResult[offset+10])
                    {
                        strcpy(tmpfile.md5,dbResult[offset+10]);
                    }
                    if(dbResult[offset+11])
                    {
                        strcpy(tmpfile.finfo,dbResult[offset+11]);
                    }
                    if(dbResult[offset+12])
                    {
                        strcpy(tmpfile.skey,dbResult[offset+12]);
                    }
                    offset += nColumn;
                    pJsonsub = cJSON_CreateObject();
                    if(pJsonsub == NULL)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
                        cJSON_Delete(ret_root);
                        return ERROR;
                    }
                    cJSON_AddItemToArray(pJsonArry,pJsonsub); 
                    cJSON_AddNumberToObject(pJsonsub,"Depens",tmpfile.depens); 
                    cJSON_AddNumberToObject(pJsonsub,"Id",tmpfile.id); 
                    cJSON_AddNumberToObject(pJsonsub,"Type",tmpfile.type); 
                    cJSON_AddNumberToObject(pJsonsub,"Size",tmpfile.size); 
                    cJSON_AddNumberToObject(pJsonsub,"LastModify",tmpfile.timestamp); 
                    cJSON_AddStringToObject(pJsonsub,"Fname",tmpfile.name);
                    cJSON_AddStringToObject(pJsonsub,"Md5",tmpfile.md5);
                    cJSON_AddStringToObject(pJsonsub,"Paths",tmpfile.path);
                    cJSON_AddStringToObject(pJsonsub,"Finfo",tmpfile.finfo);
                    cJSON_AddStringToObject(pJsonsub,"FKey",tmpfile.skey);
                }
            }
        }
        cJSON_AddItemToObject(ret_params, "Num", cJSON_CreateNumber(getnum));
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}

/**********************************************************************************
  Function:      cfd_bakfile_deal
  Description: IM模块消息处理模板函数
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
int cfd_bakfile_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = PNR_SAVEMAIL_RET_OK,uindex = 0,srcfrom = 0,i = 0,fileid= 0,newrecord = FALSE;
    long long src_fileid = 0;
    char* ret_buff = NULL;
    char userid[TOX_ID_STR_LEN+1] = {0};
    char fullpath[PNR_FILEPATH_MAXLEN+1] = {0};
    char filemd5[PNR_MD5_VALUE_MAXLEN+1] = {0};
    struct cfd_fileinfo_struct newfile;
    if(params == NULL)
    {
        return ERROR;
    }
    memset(&newfile,0,sizeof(newfile));
    //解析参数
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Depens",newfile.depens,0);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",userid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Type",newfile.type,0);
    CJSON_GET_VARLONG_BYKEYWORD(params,tmp_item,tmp_json_buff,"FileId",src_fileid,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Size",newfile.size,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"PathId",newfile.pathid,0);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Md5",newfile.md5,PNR_MD5_VALUE_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"FName",newfile.name,PNR_FILENAME_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"FKey",newfile.skey,PNR_RSA_KEY_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"FInfo",newfile.finfo,PNR_FILEINFO_MAXLEN);
    //CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"PathName",newfile.path,PNR_FILEPATH_MAXLEN);

    //参数检查
    uindex = cfd_getindexbyidstr(userid);
    //DEBUG_PRINT(DEBUG_LEVEL_INFO,"get userid(%s) uindex(%d)",userid,uindex);
    if (strlen(newfile.name) == 0 || strlen(newfile.skey)==0 || strlen(newfile.md5)==0)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_bakfile_deal:bad input");
        ret_code = CFD_BAKFILE_RETURN_BADPARAMS;
    }
    else if (src_fileid <=0 || newfile.pathid <=0 )
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_bakfile_deal:bad input fileid(%d) pathid(%d)",src_fileid,newfile.pathid);
        ret_code = CFD_BAKFILE_RETURN_BADPARAMS;
    }
    else
    {
        if((newfile.depens != CFD_DEPENDS_ADDRBOOK)&&(g_filelists[uindex].paths[newfile.pathid].depens != newfile.depens
            || strlen(g_filelists[uindex].paths[newfile.pathid].name) <= 0 || g_filelists[uindex].files_num >= CFD_FILES_MAXNUM))
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_bakfile_deal:uindex(%d) pathid(%d) file(%d)",uindex,newfile.pathid,g_filelists[uindex].files_num);
            ret_code = CFD_BAKFILE_RETURN_NOPATH;
        }
        else
        {
            memset(newfile.path,0,PNR_FILEPATH_MAXLEN);
            switch(newfile.depens)
            {
                case CFD_DEPNEDS_ALBUM:
                    srcfrom = PNR_FILE_SRCFROM_ALBUM;
                    break;
                case CFD_DEPNEDS_FOLDER:
                    srcfrom = PNR_FILE_SRCFROM_FOLDER;
                    break;
                case CFD_DEPNEDS_WXPATH:
                    srcfrom = PNR_FILE_SRCFROM_WXPATH;
                    break;
                case CFD_DEPENDS_ADDRBOOK:
                    srcfrom = PNR_FILE_SRCFROM_BAKADDRBOOK;
                    newfile.pathid = CFD_BADADDRBOOK_DEFAULTPATHID;
                    break;
                default:
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad depends(%d)",newfile.depens);
                    return ERROR;
            }
            DEBUG_PRINT(DEBUG_LEVEL_INFO,"bakfile get uindex(%d) srcfrom(%d) src_fileid(%ld:%u)",uindex,srcfrom,src_fileid,(unsigned int)src_fileid);
            PNR_REAL_FILEPATH_GET(newfile.path,uindex,srcfrom,(unsigned int)src_fileid,newfile.pathid,(char*)"");
            snprintf(fullpath, PNR_FILEPATH_MAXLEN, WS_SERVER_INDEX_FILEPATH"%s",newfile.path);
            if (access(fullpath, F_OK) != OK) 
            {
                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_bakfile_deal:file(%s) not exist",fullpath);
                ret_code = CFD_BAKFILE_RETURN_BADPARAMS;
            }
            else
            {
                md5_hash_file(fullpath, filemd5);
                if (strcmp(filemd5, newfile.md5) != OK)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_bakfile_deal:md5(%s) err",filemd5);
                    ret_code = CFD_BAKFILE_RETURN_BADPARAMS;
                }
            }
        }
    }
    //文件校验正确才保存记录
    if(ret_code == OK)
    {
        newfile.uindex = uindex;
        newfile.info_ver = DEFAULT_UINFO_VERSION;
        newfile.timestamp = (int)time(NULL);
        //备份地址簿的处理
        if(newfile.depens == CFD_DEPENDS_ADDRBOOK)
        {
            i = g_filelists[uindex].addrbook_oldest;
            g_filelists[uindex].addrbook_oldest++;
            if(g_filelists[uindex].addrbook_oldest >= CFD_BAKADDRBOOK_MAXNUM)
            {
                g_filelists[uindex].addrbook_oldest = 0;
            }
            if(g_filelists[uindex].addrbook_num < CFD_BAKADDRBOOK_MAXNUM)
            {
                newrecord = TRUE;
                g_filelists[uindex].addrbook_num++;
            }
            g_filelists[uindex].addrbook[i].uindex = uindex;
            g_filelists[uindex].addrbook[i].timestamp = newfile.timestamp;
            g_filelists[uindex].addrbook[i].info_ver = newfile.info_ver;
            g_filelists[uindex].addrbook[i].fsize = newfile.size;
            strcpy(g_filelists[uindex].addrbook[i].md5,newfile.md5);
            strcpy(g_filelists[uindex].addrbook[i].finfo,newfile.finfo);
            strcpy(g_filelists[uindex].addrbook[i].fname,newfile.name);
            strcpy(g_filelists[uindex].addrbook[i].fpath,newfile.path);
            strcpy(g_filelists[uindex].addrbook[i].fkey,newfile.skey);
            g_filelists[uindex].addrbook[i].addrnum = atoi(g_filelists[uindex].addrbook[i].finfo);
            if(newrecord == TRUE)
            {
                pnr_filelist_dbinsert(uindex,0,newfile.type,newfile.depens,srcfrom,newfile.size,newfile.pathid,newfile.fileid,"","",newfile.name,newfile.path,newfile.md5,newfile.finfo,newfile.skey,"");
                cfd_filelist_dbgetdbid_byfileid(uindex,newfile.depens,newfile.pathid,newfile.fileid,&fileid);
                g_filelists[uindex].addrbook[i].id = fileid;
            }
            else
            {
                pnr_filelist_dbupdate_fileinfoall_byfid(g_filelists[uindex].addrbook[i].id,uindex,g_filelists[uindex].addrbook[i].fsize,g_filelists[uindex].addrbook[i].timestamp,
                    g_filelists[uindex].addrbook[i].md5,g_filelists[uindex].addrbook[i].finfo,g_filelists[uindex].addrbook[i].fname,g_filelists[uindex].addrbook[i].fpath,g_filelists[uindex].addrbook[i].fkey,NULL);
            }
        }
        else//其他类型文件的处理
        {
            for(i=0;i<CFD_FILES_MAXNUM;i++)
            {
                if(g_filelists[uindex].files[i].uindex == 0)
                {
                    break;
                }
            }
            newfile.fileid = i;
            memcpy(&g_filelists[uindex].files[i],&newfile,sizeof(struct cfd_fileinfo_struct));
            pnr_filelist_dbinsert(uindex,0,newfile.type,newfile.depens,srcfrom,newfile.size,newfile.pathid,newfile.fileid,"","",newfile.name,newfile.path,newfile.md5,newfile.finfo,newfile.skey,"");
            cfd_filelist_count(uindex,newfile.pathid,TRUE,newfile.size,newfile.timestamp);
            cfd_filelist_dbgetdbid_byfileid(uindex,newfile.depens,newfile.pathid,newfile.fileid,&fileid);
            g_filelists[uindex].files[i].id = fileid;
        }
    }
    //构建响应消息
    cJSON * ret_root = cJSON_CreateObject();
    cJSON * ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_BAKFILE));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(g_imusr_array.usrnode[*plws_index].user_toxid));
    cJSON_AddItemToObject(ret_params, "SrcId", cJSON_CreateNumber(src_fileid));
    if(ret_code == PNR_SAVEMAIL_RET_OK)
    {
        cJSON_AddItemToObject(ret_params, "FileId", cJSON_CreateNumber(fileid));
        cJSON_AddItemToObject(ret_params, "PathId", cJSON_CreateNumber(newfile.pathid));
        cJSON_AddItemToObject(ret_params, "FilePath", cJSON_CreateString(newfile.path));
        if(newfile.depens == CFD_DEPENDS_ADDRBOOK)
        {
            cJSON_AddItemToObject(ret_params, "PathName", cJSON_CreateString(CFD_BADADDRBOOK_DEFAULTPATHNAME));
        }
        else
        {
            cJSON_AddItemToObject(ret_params, "PathName", cJSON_CreateString(g_filelists[uindex].paths[newfile.pathid].name));
        }
        cJSON_AddItemToObject(ret_params, "Fname", cJSON_CreateString(newfile.name));
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_fileaction_deal
  Description: IM文件处理函数
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
int cfd_fileaction_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = PNR_SAVEMAIL_RET_OK,uindex = 0,depens = 0;
    int type = 0,fid= 0, pid = 0,action = 0,i = 0;
    char* ret_buff = NULL;
    char userid[TOX_ID_STR_LEN+1] = {0};
    char name[PNR_FILEPATH_MAXLEN+1] = {0};
    char oldname[PNR_FILEPATH_MAXLEN+1] = {0};
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Depens",depens,0);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserId",userid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Type",type,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"FileId",fid,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"PathId",pid,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"React",action,0);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Name",name,PNR_FILENAME_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"OldName",oldname,PNR_FILENAME_MAXLEN);

    //参数检查
    uindex = cfd_getindexbyidstr(userid);
    if ((depens < CFD_DEPNEDS_ALBUM || depens >= CFD_DEPNEDS_BUTT)
        ||(type != CFD_FILEACTION_TYPE_FILE && type != CFD_FILEACTION_TYPE_PATH)
        ||(action < CFD_FILEACTION_REACTION_RENAME || action >= CFD_FILEACTION_REACTION_BUTT)
        ||(uindex <= 0))
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_fileaction_deal:bad input(%d:%d:%d:%s)",depens,type,action,userid);
        ret_code = CFD_FILEACTION_RETURN_BADPARAMS;
    }
    else
    {
        switch(action)
        {
            case CFD_FILEACTION_REACTION_RENAME:
                ret_code = cfd_filelist_rename(uindex,type,depens,pid,fid,name,oldname);
                break;
            case CFD_FILEACTION_REACTION_DELETE:
                ret_code = cfd_filelist_delete(uindex,type,depens,pid,fid,name);
                break;
            case CFD_FILEACTION_REACTION_CREATE:
                if(type == CFD_FILEACTION_TYPE_FILE)
                {
                    DEBUG_PRINT(DEBUG_LEVEL_ERROR,"not support");
                    ret_code = CFD_FILEACTION_RETURN_BADPARAMS;
                }
                else
                {
                    if(g_filelists[uindex].paths_num >= CFD_PATHS_MAXNUM)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"path over");
                        ret_code = CFD_FILEACTION_RETURN_NOSPACE;
                    }
                    else if(strlen(name) == 0)
                    {
                        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad path name");
                        ret_code = CFD_FILEACTION_RETURN_BADPARAMS;
                    }
                    else
                    {
                        //重名检测
                        for(i=1;i<=CFD_PATHS_MAXNUM;i++)
                        {
                            if((g_filelists[uindex].paths[i].depens == depens) &&(strcmp(name,g_filelists[uindex].paths[i].name) == OK))
                            {
                                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad path name");
                                ret_code = CFD_FILEACTION_RETURN_BADPARAMS;
                                break;
                            }
                        }
                        if(ret_code == OK)
                        {
                            for(i=1;i<=CFD_PATHS_MAXNUM;i++)
                            {
                                if(g_filelists[uindex].paths[i].type == 0)
                                {
                                    break;
                                }
                            }
                            if(i > CFD_PATHS_MAXNUM)
                            {
                                DEBUG_PRINT(DEBUG_LEVEL_ERROR,"path over");
                                ret_code = CFD_FILEACTION_RETURN_NOSPACE;
                            }
                            else  
                            {
                                cfd_filelist_addpath(uindex,i,depens,name);
                                pid = i;
                            }
                        }
                    }
                }
                break;
            default:
                ret_code = CFD_FILEACTION_RETURN_BADPARAMS;
                break;
        }
    }
    
    //构建响应消息
    cJSON * ret_root = cJSON_CreateObject();
    cJSON * ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_FILEACTION));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "React", cJSON_CreateNumber(action));
    cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(g_imusr_array.usrnode[*plws_index].user_toxid));
    if(ret_code == PNR_SAVEMAIL_RET_OK)
    {
        cJSON_AddItemToObject(ret_params, "FileId", cJSON_CreateNumber(fid));
        cJSON_AddItemToObject(ret_params, "PathId", cJSON_CreateNumber(pid));
        cJSON_AddItemToObject(ret_params, "Name", cJSON_CreateString(name));
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}
/**********************************************************************************
  Function:      cfd_bakaddrbookinfo_get_deal
  Description: 获取当前账户备份的通信录信息
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
int cfd_bakaddrbookinfo_get_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int ret_code = 0;
    int fileid = 0,i = 0;
    char userid[TOX_ID_STR_LEN+1] = {0};
    char* ret_buff = NULL;
    int uindex= 0,fid = -1;
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"User",userid,TOX_ID_STR_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"FileId",fileid,0);
    //参数检查
    uindex = cfd_getindexbyidstr(userid);
    if(uindex <= 0)
    {
        ret_code = CFD_BAKADDRUSERNUM_GET_RET_BADPARAMS;
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad userid(%s)",userid);
    }
    else
    {
        if(fileid > 0)
        {
            for(i = 0;i<CFD_BAKADDRBOOK_MAXNUM;i++)
            {
                if(g_filelists[uindex].addrbook[i].id == fileid)
                {
                    fid = i;
                    break;
                }
            }
        }
        else
        {
            //默认
            fid = 0;
        }
        if(g_filelists[uindex].addrbook[fid].fsize <= 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"User(%d) addrbook(%d) is null",uindex,fid);
            ret_code = CFD_BAKADDRUSERNUM_GET_RET_NOFOUND;
        }
    }
    //构建响应消息
    cJSON * ret_root = cJSON_CreateObject();
    cJSON * ret_params = cJSON_CreateObject();
    if(ret_root == NULL || ret_params == NULL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
        cJSON_Delete(ret_root);
        return ERROR;
    }
    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)head->api_version));
    cJSON_AddItemToObject(ret_root, "msgid", cJSON_CreateNumber((double)head->msgid));
    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_GETBAKADDRINFO));
    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
    cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(userid));
    cJSON_AddItemToObject(ret_params, "FileId", cJSON_CreateNumber(fileid));
    if(ret_code == CFD_BAKADDRUSERNUM_GET_RET_OK)
    {
        cJSON_AddItemToObject(ret_params, "Num", cJSON_CreateNumber(g_filelists[uindex].addrbook[fid].addrnum));
        cJSON_AddItemToObject(ret_params, "Fpath", cJSON_CreateString(g_filelists[uindex].addrbook[fid].fpath));
        cJSON_AddItemToObject(ret_params, "Fkey", cJSON_CreateString(g_filelists[uindex].addrbook[fid].fkey));
    }
    else
    {
        cJSON_AddItemToObject(ret_params, "Num", cJSON_CreateNumber(0));
        cJSON_AddItemToObject(ret_params, "Fpath", cJSON_CreateString(""));
        cJSON_AddItemToObject(ret_params, "Fkey", cJSON_CreateString(""));
    }
    cJSON_AddItemToObject(ret_root, "params", ret_params);
    ret_buff = cJSON_PrintUnformatted(ret_root);
    cJSON_Delete(ret_root);
    *retmsg_len = strlen(ret_buff);
    if(*retmsg_len < TOX_ID_STR_LEN || *retmsg_len >= IM_JSON_MAXLEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"bad ret(%d,%s)",*retmsg_len,ret_buff);
        free(ret_buff);
        return ERROR;
    }
    strcpy(retmsg,ret_buff);
    free(ret_buff);
    return OK;
}

/**********************************************************************************
  Function:      cfd_nodeonline_notice_deal
  Description: 节点上线消息
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
int cfd_nodeonline_notice_deal(cJSON * params,char* retmsg,int* retmsg_len,
	int* plws_index, struct imcmd_msghead_struct *head)
{
    char* tmp_json_buff = NULL;
    cJSON* tmp_item = NULL;
    int rid = 0,modify_flag = FALSE,i = 0;
    char usrinfo_cache[ID_CODE_STRING_MAXLEN+1] = {0};
    cJSON* users_root = NULL;
    cJSON* uinfo = NULL;
    if(params == NULL)
    {
        return ERROR;
    }
    //解析参数
    pthread_mutex_lock(&g_onlinemsg_lock);
    memset(&g_onlinemsg,0,sizeof(g_onlinemsg));
    memset(g_cacheonline_data,0,IM_MSG_PAYLOAD_MAXLEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Mac",g_onlinemsg.head.mac,MACSTR_MAX_LEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Type",g_onlinemsg.head.type,0);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"Weight",g_onlinemsg.head.weight,0);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"NodeId",g_onlinemsg.head.nodeid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"RouteId",g_onlinemsg.head.routeid,TOX_ID_STR_LEN);
    CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Rname",g_onlinemsg.head.rname,PNR_FILENAME_MAXLEN);
    CJSON_GET_VARINT_BYKEYWORD(params,tmp_item,tmp_json_buff,"UserNum",g_onlinemsg.head.innode_usernum,0);

    //参数检查
    if(strlen(g_onlinemsg.head.nodeid) != TOX_ID_STR_LEN)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_nodeonline_notice_deal:bad nodeid(%s)",g_onlinemsg.head.nodeid);
        pthread_mutex_unlock(&g_onlinemsg_lock);
        return ERROR;
    }
    rid = cfd_rnodelist_getid_bydevid(CFD_NODE_TOXID_NID,g_onlinemsg.head.nodeid);
    if(rid <= 0)
    {
        //这里要排除设备重置导致nodeid变更的情况
        if(strlen(g_onlinemsg.head.mac) > MAC_LEN)
        {
            int old_rid = 0;
            old_rid = cfd_rnodedbid_dbget_bymac(g_onlinemsg.head.mac);
            if(old_rid > CFD_RNODE_DEFAULT_RID)
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"DEV mac(%s) renew",g_onlinemsg.head.mac);
                cfd_rnode_dbdelte_byid(old_rid);
            }
        }
        //新的节点
        rid = cfd_rnodelist_getidleid();
        if(rid <= 0)
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"cfd_nodeonline_notice_deal:get idle nodeid failed");
            pthread_mutex_unlock(&g_onlinemsg_lock);
            return ERROR;
        }
        memset(&g_rlist_node[rid],0,sizeof(struct cfd_nodeinfo_struct));
        g_rlist_node[rid].id = rid;
        g_rlist_node[rid].type = g_onlinemsg.head.type;
        g_rlist_node[rid].weight = g_onlinemsg.head.weight;
        strcpy(g_rlist_node[rid].mac,g_onlinemsg.head.mac);
        strcpy(g_rlist_node[rid].nodeid,g_onlinemsg.head.nodeid);
        strcpy(g_rlist_node[rid].routeid,g_onlinemsg.head.routeid);
        strcpy(g_rlist_node[rid].rname,g_onlinemsg.head.rname);
        cfd_rnodelist_dbinsert(&g_rlist_node[rid]);
        if(rid > CFD_RNODE_DEFAULT_RID)
        {
            g_rlist_node[rid].node_fid = check_and_add_friends(g_daemon_tox.ptox_handle,g_rlist_node[rid].nodeid,g_daemon_tox.userinfo_fullurl);
            if(g_rlist_node[rid].node_fid < 0)
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add friend(%s) failed",g_rlist_node[rid].nodeid);
                g_rlist_node[rid].node_cstatus = CFD_RID_NODE_CSTATUS_CONNETERR;
            }
            else
            {
                DEBUG_PRINT(DEBUG_LEVEL_INFO, "check add friend(%s) OK",g_rlist_node[rid].nodeid);
                g_rlist_node[rid].node_cstatus = CFD_RID_NODE_CSTATUS_CONNETTING;
            }
        }
    }
    else
    {
        if(strcmp(g_rlist_node[rid].mac,g_onlinemsg.head.mac) != OK)
        {
            modify_flag = TRUE;
            memset(g_rlist_node[rid].mac,0,MACSTR_MAX_LEN);
            strcpy(g_rlist_node[rid].mac,g_onlinemsg.head.mac);
        }
        if(strcmp(g_rlist_node[rid].routeid,g_onlinemsg.head.routeid) != OK)
        {
            modify_flag = TRUE;
            memset(g_rlist_node[rid].routeid,0,TOX_ID_STR_LEN);
            strcpy(g_rlist_node[rid].routeid,g_onlinemsg.head.routeid);
        }
        if(strcmp(g_rlist_node[rid].rname,g_onlinemsg.head.rname) != OK)
        {
            modify_flag = TRUE;
            memset(g_rlist_node[rid].rname,0,PNR_USERNAME_MAXLEN);
            strcpy(g_rlist_node[rid].rname,g_onlinemsg.head.rname);
        }
        if(g_rlist_node[rid].type != g_onlinemsg.head.type)
        {
            modify_flag = TRUE;
            g_rlist_node[rid].type = g_onlinemsg.head.type;
        }
        if(g_rlist_node[rid].weight != g_onlinemsg.head.weight)
        {
            modify_flag = TRUE;
            g_rlist_node[rid].weight = g_onlinemsg.head.weight;
        }
        if(modify_flag == TRUE)
        {
            cfd_rnode_dbupdate_byid(&g_rlist_node[rid]);
        }
    }
    if (g_onlinemsg.head.innode_usernum > 0)
    {
        CJSON_GET_VARSTR_BYKEYWORD(params,tmp_item,tmp_json_buff,"Users",g_cacheonline_data,IM_MSG_PAYLOAD_MAXLEN);
        users_root = cJSON_Parse(g_cacheonline_data);
        if(users_root == NULL) 
        {
            DEBUG_PRINT(DEBUG_LEVEL_ERROR,"get users_root failed");
            pthread_mutex_unlock(&g_onlinemsg_lock);
            return ERROR;
        }
        for(i = 0; i< g_onlinemsg.head.innode_usernum ;i++)
        {
            uinfo = cJSON_GetArrayItem(users_root,i);
            if(uinfo != NULL)
            {
                memset(usrinfo_cache,0,ID_CODE_STRING_MAXLEN);
                CJSON_GET_VARSTR_BYKEYWORD(uinfo,tmp_item,tmp_json_buff,"User",usrinfo_cache,ID_CODE_STRING_MAXLEN);
                sscanf(usrinfo_cache,"%d,%d,%d,%d,%d,%d,%s",&g_onlinemsg.users[i].uid,&g_onlinemsg.users[i].index,&g_onlinemsg.users[i].friend_seq,
                    &g_onlinemsg.users[i].uinfo_seq,&g_onlinemsg.users[i].last_active,&g_onlinemsg.users[i].active_rid,g_onlinemsg.users[i].idstr);
                DEBUG_PRINT(DEBUG_LEVEL_INFO,"###get user(%d:%d:%s) active_rid(%d) friend_seq(%d) uinfo_seq(%d) last_active(%d)",
                    i,g_onlinemsg.users[i].uid,g_onlinemsg.users[i].idstr,g_onlinemsg.users[i].active_rid,g_onlinemsg.users[i].friend_seq,g_onlinemsg.users[i].uinfo_seq,g_onlinemsg.users[i].last_active);
                if(g_onlinemsg.users[i].active_rid == CFD_RNODE_DEFAULT_RID)
                {
                    g_onlinemsg.users[i].active_rid = rid;
                }
                else
                {
                    g_onlinemsg.users[i].active_rid = 0;
                }
                cfd_uactive_update_byidstr(&g_onlinemsg.users[i]);
            }
        }
    }
    pthread_mutex_unlock(&g_onlinemsg_lock);
    return OK;
}
/*****************************************************************************
 函 数 名  : rnode_monitor_friends_thread
 功能描述  : 自我监测节点好友任务
 输入参数  : void arg  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
void *rnode_monitor_friends_thread(void *para)
{	
    int i = 0,f_status = 0;
    TOX_ERR_FRIEND_QUERY err;
    while(g_p2pnet_init_flag != CFD_NODE_TOXID_ALL)
    {
        sleep(1);
    }
	while (TRUE) 
    {
        for(i=CFD_RNODE_DEFAULT_RID+1;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(g_rlist_node[i].nodeid[0] != 0 && g_rlist_node[i].node_fid > 0)
            {
                if(g_rlist_node[i].node_cstatus != CFD_RID_NODE_CSTATUS_CONNETTED)
                {
                    f_status = tox_friend_get_status(g_daemon_tox.ptox_handle,g_rlist_node[i].node_fid,&err);
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"rnode(%d:%s) status(%d)",g_rlist_node[i].node_fid,g_rlist_node[i].nodeid,f_status);
                }
                else
                {
                    f_status =tox_friend_get_connection_status(g_daemon_tox.ptox_handle,g_rlist_node[i].node_fid,&err);
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"rnode(%d:%s) conectstatus(%d)",g_rlist_node[i].node_fid,g_rlist_node[i].nodeid,f_status);
                }
            }
        }
        sleep(PNR_SELF_MONITOR_CYCLE);
    }
	return NULL;  
}
/*****************************************************************************
 函 数 名  : rnode_friends_status_show
 功能描述  : 显示当前节点好友状态
 输入参数  : void arg  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月30日
    作    者   : willcao
    修改内容   : 新生成函数

*****************************************************************************/
int rnode_friends_status_show(int node_flag)
{	
    int i = 0,f_status = 0,con_status = 0;
    TOX_ERR_FRIEND_QUERY err;
    if(g_p2pnet_init_flag != CFD_NODE_TOXID_ALL)
    {
        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"rnode_friends_status_show:bad g_p2pnet_init_flag(%d) ERR",g_p2pnet_init_flag);
        return ERROR;
    }
    if(node_flag == CFD_NODE_TOXID_NID)
    {
        for(i=CFD_RNODE_DEFAULT_RID+1;i<=CFD_RNODE_MAXNUM;i++)
        {
            if(g_rlist_node[i].id > 0)
            {
                if(g_rlist_node[i].node_fid >= 0)
                {
                    f_status = tox_friend_get_status(g_daemon_tox.ptox_handle,g_rlist_node[i].node_fid,&err);
                    con_status = tox_friend_get_connection_status(g_daemon_tox.ptox_handle,g_rlist_node[i].node_fid,&err);
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"rnode(%d:%s) fstatus(%d) conectstatus(%d,%d)",g_rlist_node[i].node_fid,g_rlist_node[i].nodeid,f_status,g_rlist_node[i].node_cstatus,con_status);
                }
                else
                {
                    DEBUG_PRINT(DEBUG_LEVEL_INFO,"rnode(%d:%s) node_fid(%d)",i,g_rlist_node[i].nodeid,f_status,g_rlist_node[i].node_fid);
                }
            }
        }
    }
	return OK;  
}

