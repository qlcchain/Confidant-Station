#include "tox_seg_msg.h"
#include "common_lib.h"

struct list_head g_tox_msg_send_list = LIST_HEAD_INIT(g_tox_msg_send_list);
pthread_rwlock_t g_tox_msg_send_lock = PTHREAD_RWLOCK_INITIALIZER;

/*****************************************************************************
 函 数 名  : tox_seg_msg_process
 功能描述  : 处理APP发送的数据包片段请求
 输入参数  : Tox *m                                 
             int friendnum                          
             struct imcmd_msghead_struct *msg_head  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月29日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void tox_seg_msg_process(Tox *m, int friendnum, struct imcmd_msghead_struct *msg_head)
{
	struct tox_msg_send *pos = NULL;
    struct tox_msg_send *n = NULL;
    char msg[MAX_SEND_DATA_SIZE + 1] = {0};
    int more = 0;

    pthread_rwlock_wrlock(&g_tox_msg_send_lock);
    list_for_each_safe(pos, n, &g_tox_msg_send_list, struct tox_msg_send, list) {
        if (pos->msgid == msg_head->msgid && pos->friendnum == friendnum && 
			pos->offset == msg_head->offset) {
			pos->recvtime = time(NULL);
				
            if (pos->msglen - pos->offset > MAX_SEND_DATA_SIZE) {
                memcpy(msg, pos->msg + pos->offset, MAX_SEND_DATA_SIZE);
                more = 1;
            } else {
                memcpy(msg, pos->msg + pos->offset, pos->msglen - pos->offset);
            }

            cJSON *RspJsonSend = cJSON_Parse(pos->frame);
			if (!RspJsonSend) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, "parse frame(%s) err!", pos->frame);
				list_del(&pos->list);
				free(pos->msg);
                free(pos);
                break;
			}
			
			cJSON_AddStringToObject(RspJsonSend, "params", msg);
        	cJSON_AddNumberToObject(RspJsonSend, "more", more);
        	cJSON_AddNumberToObject(RspJsonSend, "offset", pos->offset);

			char *RspStrSend = cJSON_PrintUnformatted(RspJsonSend);
			if (!RspStrSend) {
				DEBUG_PRINT(DEBUG_LEVEL_ERROR, "print RspJsonSend err!");
				cJSON_Delete(RspJsonSend);
				break;
			}

			tox_friend_send_message(m, friendnum, TOX_MESSAGE_TYPE_NORMAL, 
        		(uint8_t *)RspStrSend, strlen(RspStrSend), NULL);

			cJSON_Delete(RspJsonSend);
			free(RspStrSend);

			if (more) {
				pos->offset += MAX_SEND_DATA_SIZE;
			} else {
				list_del(&pos->list);
				free(pos->msg);
                free(pos);
			}

			break;
        }
    }
    pthread_rwlock_unlock(&g_tox_msg_send_lock);
}

/*****************************************************************************
 函 数 名  : tox_seg_msg_flush
 功能描述  : 清除过期消息
 输入参数  : void  
 输出参数  : 无
 返 回 值  : 
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年11月29日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
void *tox_seg_msg_flush(void *para)
{
	struct tox_msg_send *pos = NULL;
    struct tox_msg_send *n = NULL;
	int nowtime = 0;

	while (1) {
		nowtime = time(NULL);
		
	    pthread_rwlock_wrlock(&g_tox_msg_send_lock);
	    list_for_each_safe(pos, n, &g_tox_msg_send_list, struct tox_msg_send, list) {
			if (nowtime - pos->recvtime > 60) {
				list_del(&pos->list);
				free(pos);
			}
		}
		pthread_rwlock_unlock(&g_tox_msg_send_lock);

		sleep(1);
	}
}

