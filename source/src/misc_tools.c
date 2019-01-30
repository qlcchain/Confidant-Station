/*  misc_tools.c
 *
 *
 *  Copyright (C) 2014 Toxic All Rights Reserved.
 *
 *  This file is part of Toxic.
 *
 *  Toxic is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  Toxic is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with Toxic.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "misc_tools.h"
time_t get_unix_time(void)
{
    return time(NULL);
}

/* Returns 1 if connection has timed out, 0 otherwise */
int timed_out(time_t timestamp, time_t timeout)
{
    return timestamp + timeout <= get_unix_time();
}

/* Get the current local time */
struct tm *get_time(void)
{
    struct tm *timeinfo;
    time_t t = get_unix_time();
    timeinfo = localtime((const time_t *) &t);
    return timeinfo;
}

/*Puts the current time in buf in the format of [HH:mm:ss] */
/*
void get_time_str(char *buf, int bufsize)
{
   if (user_settings->timestamps == TIMESTAMPS_OFF) {
       buf[0] = '\0';
        return;
    }

    const char *t = user_settings->timestamp_format;
    strftime(buf, bufsize, t, get_time());
}
*/
/* Converts seconds to string in format HH:mm:ss; truncates hours and minutes when necessary */
void get_elapsed_time_str(char *buf, int bufsize, time_t secs)
{
    if (!secs)
        return;

    long int seconds = secs % 60;
    long int minutes = (secs % 3600) / 60;
    long int hours = secs / 3600;

    if (!minutes && !hours)
        snprintf(buf, bufsize, "%.2ld", seconds);
    else if (!hours)
        snprintf(buf, bufsize, "%ld:%.2ld", minutes, seconds);
    else
        snprintf(buf, bufsize, "%ld:%.2ld:%.2ld", hours, minutes, seconds);
}

// You are responsible for freeing the return value!
uint8_t *hex_string_to_bin(const char *hex_string)
{
    // byte is represented by exactly 2 hex digits, so lenth of binary string
    // is half of that of the hex one. only hex string with even length
    // valid. the more proper implementation would be to check if strlen(hex_string)
    // is odd and return error code if it is. we assume strlen is even. if it's not
    // then the last byte just won't be written in 'ret'.
    size_t i, len = strlen(hex_string) / 2;
    uint8_t *ret = (uint8_t *)malloc(len);
    const char *pos = hex_string;

    for (i = 0; i < len; ++i, pos += 2) {
        sscanf(pos, "%2hhx", &ret[i]);
    }
/*
	printf("%d public key is \n",len);
	for(i=0;i<len;i++)
	{
		printf("%2hhx",ret[i]);
	}
	printf("%d public key is \n",len);
*/
    return ret;
}

/*
 * Converts a hexidecimal string of length hex_len to binary format and puts the result in output.
 * output_size must be exactly half of hex_len.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int hex_string_to_bin_s(const char *hex_string, size_t hex_len, char *output, size_t output_size)
{
	size_t i = 0;
    if (output_size == 0 || hex_len != output_size * 2)
        return -1;

    for (i = 0; i < output_size; ++i) {
        sscanf(hex_string, "%2hhx", &output[i]);
        hex_string += 2;
    }

    return 0;
}


int hex_string_to_bytes(char *buf, int size, const char *keystr)
{
    if (size % 2 != 0)
        return -1;

    int i, res;
    const char *pos = keystr;

    for (i = 0; i < size; ++i) {
        res = sscanf(pos, "%2hhx", &buf[i]);
        pos += 2;

        if (res == EOF || res < 1)
            return -1;
    }

    return 0;
}









/* returns index of the first instance of ch in s starting at idx.
   returns length of s if char not found or 0 if s is NULL. */
int char_find(int idx, const char *s, char ch)
{
    if (!s) {
        return 0;
    }

    int i = idx;

    for (i = idx; s[i]; ++i) {
        if (s[i] == ch)
            break;
    }

    return i;
}

/* checks if a file exists. Returns true or false */
bool file_exists(const char *path)
{
    struct stat s;
    return stat(path, &s) == 0;
}

/* Return true if address appears to be a valid ipv4 address. */
bool is_ip4_address(const char *address)
{
    struct sockaddr_in s_addr;
    return inet_pton(AF_INET, address, &(s_addr.sin_addr)) != 0;
}

/* Return true if address roughly appears to be a valid ipv6 address.
 *
 * TODO: Improve this function (inet_pton behaves strangely with ipv6).
 * for now the only guarantee is that it won't return true if the
 * address is a domain or ipv4 address, and should only be used if you're
 * reasonably sure that the address is one of the three (ipv4, ipv6 or a domain).
 */
bool is_ip6_address(const char *address)
{
    size_t i;
    size_t num_colons = 0;
    char ch = 0;

    for (i = 0; (ch = address[i]); ++i) {
        if (ch == '.') {
            return false;
        }

        if (ch == ':') {
            ++num_colons;
        }
    }

    return num_colons > 1 && num_colons < 8;
}
