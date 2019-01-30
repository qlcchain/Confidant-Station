/*
 * Handle friend requests.
 */

/*
 * Copyright 漏 2016-2018 The TokTok team.
 * Copyright 漏 2013 Tox project.
 *
 * This file is part of Tox, the free peer to peer instant messenger.
 *
 * Tox is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Tox is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Tox.  If not, see <http://www.gnu.org/licenses/>.
 */
#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "friend_requests.h"

#include <stdlib.h>
#include <string.h>

#include "util.h"
#include "common_lib.h"

/* NOTE: The following is just a temporary fix for the multiple friend requests received at the same time problem.
 * TODO(irungentoo): Make this better (This will most likely tie in with the way we will handle spam.)
 */
#define MAX_RECEIVED_STORED 32

struct Received_Requests {
    uint8_t requests[MAX_RECEIVED_STORED][CRYPTO_PUBLIC_KEY_SIZE];
	uint8_t messages[MAX_RECEIVED_STORED][MAX_FRIEND_REQUEST_DATA_SIZE];
    uint16_t requests_index;
};

struct Friend_Requests {
    uint32_t nospam;
    fr_friend_request_cb *handle_friendrequest;
    uint8_t handle_friendrequest_isset;
    void *handle_friendrequest_object;

    filter_function_cb *filter_function;
    void *filter_function_userdata;

    struct Received_Requests received;
};

/* Set and get the nospam variable used to prevent one type of friend request spam. */
void set_nospam(Friend_Requests *fr, uint32_t num)
{
    fr->nospam = num;
}

uint32_t get_nospam(const Friend_Requests *fr)
{
    return fr->nospam;
}


/* Set the function that will be executed when a friend request is received. */
void callback_friendrequest(Friend_Requests *fr, fr_friend_request_cb *function, void *object)
{
    fr->handle_friendrequest = function;
    fr->handle_friendrequest_isset = 1;
    fr->handle_friendrequest_object = object;
}

/* Set the function used to check if a friend request should be displayed to the user or not. */
void set_filter_function(Friend_Requests *fr, filter_function_cb *function, void *userdata)
{
    fr->filter_function = function;
    fr->filter_function_userdata = userdata;
}

/* Add to list of received friend requests. */
static void addto_receivedlist(Friend_Requests *fr, const uint8_t *real_pk)
{
    if (fr->received.requests_index >= MAX_RECEIVED_STORED) {
        fr->received.requests_index = 0;
    }

    id_copy(fr->received.requests[fr->received.requests_index], real_pk);
    ++fr->received.requests_index;
}

/*****************************************************************************
 函 数 名  : addto_receivedlist_with_message
 功能描述  : 把pk和message一起放入接收列表
 输入参数  : Friend_Requests *fr     
             const uint8_t *real_pk  
             uint8_t *message        
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月4日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static void addto_receivedlist_with_message(Friend_Requests *fr, const uint8_t *real_pk, uint8_t *message)
{
    if (fr->received.requests_index >= MAX_RECEIVED_STORED) {
        fr->received.requests_index = 0;
    }

    id_copy(fr->received.requests[fr->received.requests_index], real_pk);
	strncpy((char *)fr->received.messages[fr->received.requests_index], (char *)message, MAX_FRIEND_REQUEST_DATA_SIZE - 1);
    ++fr->received.requests_index;
}


/* Check if a friend request was already received.
 *
 *  return false if it did not.
 *  return true if it did.
 */
static bool request_received(const Friend_Requests *fr, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received.requests[i], real_pk)) {
            return true;
        }
    }

    return false;
}

/*****************************************************************************
 函 数 名  : request_with_message_received
 功能描述  : 带相同消息的好友亲请求是否已经收到过
 输入参数  : const Friend_Requests *fr  
             const uint8_t *real_pk     
             const uint8_t *message     
 输出参数  : 无
 返 回 值  : static
 调用函数  : 
 被调函数  : 
 
 修改历史      :
  1.日    期   : 2018年12月4日
    作    者   : lichao
    修改内容   : 新生成函数

*****************************************************************************/
static bool request_with_message_received(const Friend_Requests *fr, const uint8_t *real_pk, uint8_t *message)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received.requests[i], real_pk)) {
			if (!strcmp((char *)fr->received.messages[i], (char *)message)) {
            	return true;
			}
        }
    }

    return false;
}

/* Remove real pk from received.requests list.
 *
 *  return 0 if it removed it successfully.
 *  return -1 if it didn't find it.
 */
int remove_request_received(Friend_Requests *fr, const uint8_t *real_pk)
{
    for (uint32_t i = 0; i < MAX_RECEIVED_STORED; ++i) {
        if (id_equal(fr->received.requests[i], real_pk)) {
            crypto_memzero(fr->received.requests[i], CRYPTO_PUBLIC_KEY_SIZE);
            return 0;
        }
    }

    return -1;
}


static int friendreq_handlepacket(void *object, const uint8_t *source_pubkey, const uint8_t *packet, uint16_t length,
                                  void *userdata)
{
    Friend_Requests *const fr = (Friend_Requests *)object;

    if (length <= 1 + sizeof(fr->nospam) || length > ONION_CLIENT_MAX_DATA_SIZE) {
        return 1;
    }

    ++packet;
    --length;

	/*
    if (fr->handle_friendrequest_isset == 0) {
        return 1;
    }
	*/

	const uint32_t message_len = length - sizeof(fr->nospam);
    VLA(uint8_t, message, message_len + 1);
    memcpy(message, packet + sizeof(fr->nospam), message_len);
    message[SIZEOF_VLA(message) - 1] = 0; /* Be sure the message is null terminated. */

	DEBUG_PRINT(DEBUG_LEVEL_INFO, "request friend(%s)", message);
		
	/*
    if (request_received(fr, source_pubkey)) {
        return 1;
    }

	if (request_with_message_received(fr, source_pubkey, message)) {
		return 1;
	}
	
    if (memcmp(packet, &fr->nospam, sizeof(fr->nospam)) != 0) {
		printf("nospam return\n");
        return 1;
    }

    if (fr->filter_function) {
        if (fr->filter_function(source_pubkey, fr->filter_function_userdata) != 0) {
			printf("filter return\n");
			return 1;
        }
    }
	*/
	
    //addto_receivedlist(fr, source_pubkey);
    //addto_receivedlist_with_message(fr, source_pubkey, message);

    fr->handle_friendrequest(fr->handle_friendrequest_object, source_pubkey, message, message_len, userdata);
    return 0;
}

void friendreq_init(Friend_Requests *fr, Friend_Connections *fr_c)
{
    set_friend_request_callback(fr_c, &friendreq_handlepacket, fr);
}

Friend_Requests *friendreq_new(void)
{
    return (Friend_Requests *)calloc(1, sizeof(Friend_Requests));
}

void friendreq_kill(Friend_Requests *fr)
{
    free(fr);
}
