#include "upload.h"
#include "pn_imserver.h"

static const char * const param_names[] = {
	"Action",
	"FromId",
	"ToId",
	"FileName",
	"FileSize",
	"MD5"
};

enum enum_param_names {
	EPN_ACTION,
	EPN_FID,
	EPN_TID,
	EPN_FNAME,
	EPN_FSIZE,
	EPN_MD5
};

extern int im_pushmsg_callback(int index,int cmd,int local_flag,int apiversion,void* params);
/*****************************************************************************
 函 数 名  : file_upload_cb
 功能描述  : 文件上传回调
 输入参数  : void *data                            
             const char *name                      
             const char *filename                  
             char *buf                             
             int len                               
             enum lws_spa_fileupload_states state  
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年9月27日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static int file_upload_cb(void *data, const char *name, const char *filename,
	       char *buf, int len, enum lws_spa_fileupload_states state)
{
	struct pss *pss = (struct pss *)data;
	int n;

	switch (state) {
	case LWS_UFS_OPEN:
		/* take a copy of the provided filename */
		lws_strncpy(pss->filename, filename, sizeof(pss->filename) - 1);
		/* remove any scary things like .. */
		lws_filename_purify_inplace(pss->filename);
		/* open a file of that name for write in the cwd */
		pss->fd = open(pss->filename, O_CREAT | O_TRUNC | O_RDWR, 0600);
		if (pss->fd == LWS_INVALID_FILE) {
			lwsl_notice("Failed to open output file %s\n",
				    pss->filename);
			return 1;
		}
		break;
	case LWS_UFS_FINAL_CONTENT:
	case LWS_UFS_CONTENT:
		if (len) {
			pss->file_length += len;

			n = write(pss->fd, buf, len);
			if (n < len) {
				lwsl_notice("Problem writing file %d\n", errno);
			}
		}
		if (state == LWS_UFS_CONTENT)
			/* wasn't the last part of the file */
			break;

		/* the file upload is completed */

		lwsl_user("%s: upload done, written %lld to %s\n", __func__,
			  pss->file_length, pss->filename);

		close(pss->fd);
		pss->fd = LWS_INVALID_FILE;
		break;
	}

	return 0;
}

/*****************************************************************************
 函 数 名  : callback_upload
 功能描述  : 处理文件上传接口
 输入参数  : struct lws *wsi                   
             enum lws_callback_reasons reason  
             void *user                        
             void *in                          
             size_t len                        
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年9月27日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
int callback_upload(struct lws *wsi, enum lws_callback_reasons reason, void *user,
	      void *in, size_t len)
{
	struct pss *pss = (struct pss *)user;
	int n;
    int ret_code = 0;
    char *ret_buff = NULL;
    int index = 0;
	int param_invalid = 0;
	struct im_sendfile_struct msg;
	char filemd5[33] = {0};
	char filename[256] = {0};
	char fullfilename[256] = {0};

	switch (reason) {
	case LWS_CALLBACK_HTTP:

		/*
		 * Manually report that our form target URL exists
		 *
		 * you can also do this by adding a mount for the form URL
		 * to the protocol with type LWSMPRO_CALLBACK, then no need
		 * to trap LWS_CALLBACK_HTTP.
		 */

		if (!strcmp((const char *)in, "/form1"))
			/* assertively allow it to exist in the URL space */
			return 0;

		/* default to 404-ing the URL if not mounted */
		break;

	case LWS_CALLBACK_HTTP_BODY:

		/* create the POST argument parser if not already existing */

		if (!pss->spa) {
			pss->spa = lws_spa_create(wsi, param_names,
					LWS_ARRAY_SIZE(param_names), 10240000,
					file_upload_cb, pss);
			if (!pss->spa)
				return -1;
		}

		/* let it parse the POST data */
		if (lws_spa_process(pss->spa, in, (int)len))
			return -1;

		break;

	case LWS_CALLBACK_HTTP_BODY_COMPLETION:

		/* inform the spa no more payload data coming */

		lws_spa_finalize(pss->spa);
		
		memset(&msg, 0, sizeof(msg));
		msg.msgtype = PNR_IM_MSGTYPE_FILE;
		
		for (n = 0; n < (int)LWS_ARRAY_SIZE(param_names); n++) {
			if (!lws_spa_get_string(pss->spa, n)) {
				lwsl_user("%s: undefined\n", param_names[n]);
				param_invalid = 1;
			} else {
				switch (n) {
				case EPN_FID:
					strncpy(msg.fromuser_toxid, lws_spa_get_string(pss->spa, n), TOX_ID_STR_LEN);
					break;
				case EPN_TID:
					strncpy(msg.touser_toxid, lws_spa_get_string(pss->spa, n), TOX_ID_STR_LEN);
					break;
				case EPN_FNAME:
					strncpy(msg.filename, lws_spa_get_string(pss->spa, n), UPLOAD_FILENAME_MAXLEN - 1);
					break;
				case EPN_FSIZE:
					msg.filesize = strtoul(lws_spa_get_string(pss->spa, n), NULL, 0);
					break;
				case EPN_MD5:
					strncpy(msg.md5, lws_spa_get_string(pss->spa, n), 32);
					break;	
				}
				
				lwsl_user("%s: (len %d) '%s'\n",
				    param_names[n],
				    lws_spa_get_length(pss->spa, n),
				    lws_spa_get_string(pss->spa, n));
			}
		}

		snprintf(filename, sizeof(filename), "/usr/%s", msg.filename);
		md5_hash_file(filename, filemd5);

		if (param_invalid) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "invalid paras");
			ret_code = PNR_MSGSEND_RETCODE_FAILED;
		} else if(strcmp(msg.fromuser_toxid, msg.touser_toxid) == OK) {
	       DEBUG_PRINT(DEBUG_LEVEL_ERROR, "userid repeat(%s->%s)",
	            msg.fromuser_toxid, msg.touser_toxid); 
	       ret_code = PNR_MSGSEND_RETCODE_FAILED;
	    } else if(msg.filesize > 100*1024*1024) {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "file too big(%d)", msg.filesize); 
	        ret_code = PNR_MSGSEND_RETCODE_FAILED;  
	    } else if (strcmp(filemd5, msg.md5)) {
			DEBUG_PRINT(DEBUG_LEVEL_ERROR, "file md5 err(%s-%s)", msg.md5, filemd5); 
	        ret_code = PNR_MSGSEND_RETCODE_FAILED;
		} else {
	        //查询是否已经存在的实例
	        index = get_indexbytoxid(msg.fromuser_toxid);
	        if (index == 0) {
	            //清除对应记录
	            ret_code = PNR_MSGSEND_RETCODE_FAILED;
	            DEBUG_PRINT(DEBUG_LEVEL_INFO, "get fromuser_toxid(%s) failed", msg.fromuser_toxid);
	        } else {
				//文件放到用户自己的目录
				snprintf(fullfilename, sizeof(fullfilename), DAEMON_PNR_USERDATA_DIR "user%d/%s", 
					index, msg.filename);
				rename(filename, fullfilename);
			
	            //pnr_msglog_dbinsert(index, msg.msgtype, &msg.log_id, msg.fromuser_toxid,
				//	msg.touser_toxid, fullfilename, msg.md5);
				
	            ret_code = PNR_USER_ADDFRIEND_RETOK;
	            //i = get_indexbytoxid(msg.touser_toxid);
	            //对于目标好友为本地用户
	            //if (i != 0)
	            //    im_pushmsg_callback(i, PNR_IM_CMDTYPE_SENDFILE, TRUE, (void *)&msg);
	            //else
	            //    im_pushmsg_callback(index, PNR_IM_CMDTYPE_SENDFILE, FALSE, (void *)&msg);
	        }
	    }
	    
	    //构建响应消息
		cJSON * ret_root =  cJSON_CreateObject();
	    cJSON * ret_params =  cJSON_CreateObject();
	    if (ret_root == NULL || ret_params == NULL) {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR,"err");
	        cJSON_Delete(ret_root);
	        return ERROR;
	    }
		
	    cJSON_AddItemToObject(ret_root, "appid", cJSON_CreateString("MIFI"));
	    cJSON_AddItemToObject(ret_root, "timestamp", cJSON_CreateNumber((double)time(NULL)));
	    cJSON_AddItemToObject(ret_root, "apiversion", cJSON_CreateNumber((double)PNR_API_VERSION_V1));

	    cJSON_AddItemToObject(ret_params, "Action", cJSON_CreateString(PNR_IMCMD_SENDFILE));
	    cJSON_AddItemToObject(ret_params, "RetCode", cJSON_CreateNumber(ret_code));
	    cJSON_AddItemToObject(ret_params, "MsgId", cJSON_CreateNumber(msg.log_id));
	    cJSON_AddItemToObject(ret_params, "FromId", cJSON_CreateString(msg.fromuser_toxid));
	    cJSON_AddItemToObject(ret_params, "ToId", cJSON_CreateString(msg.touser_toxid));
	    cJSON_AddItemToObject(ret_params, "FileName", cJSON_CreateString(msg.filename));
		cJSON_AddItemToObject(ret_params, "FileSize", cJSON_CreateNumber(msg.filesize));
		cJSON_AddItemToObject(ret_params, "MD5", cJSON_CreateString(msg.md5));
	    cJSON_AddItemToObject(ret_root, "params", ret_params);

	    ret_buff = cJSON_PrintUnformatted(ret_root);
	    cJSON_Delete(ret_root);
	    
	    if (strlen(ret_buff) < TOX_ID_STR_LEN || strlen(ret_buff) >= IM_JSON_MAXLEN) {
	        DEBUG_PRINT(DEBUG_LEVEL_ERROR, "bad ret(%d)", strlen(ret_buff));
	        free(ret_buff);
	        return ERROR;
	    }
		
		lws_return_http_status(wsi, HTTP_STATUS_OK, ret_buff);
		free(ret_buff);
		
		break;

	case LWS_CALLBACK_HTTP_DROP_PROTOCOL:
		/* called when our wsi user_space is going to be destroyed */
		if (pss->spa) {
			lws_spa_destroy(pss->spa);
			pss->spa = NULL;
		}
		break;

	default:
		break;
	}

	return 0;
}

