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
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <dirent.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <stdint.h>
#include <stdbool.h>



time_t get_unix_time(void);

/* Returns 1 if connection has timed out, 0 otherwise */
int timed_out(time_t timestamp, time_t timeout);


/* Get the current local time */
struct tm *get_time(void);


uint8_t *hex_string_to_bin(const char *hex_string);


/*
 * Converts a hexidecimal string of length hex_len to binary format and puts the result in output.
 * output_size must be exactly half of hex_len.
 *
 * Returns 0 on success.
 * Returns -1 on failure.
 */
int hex_string_to_bin_s(const char *hex_string, size_t hex_len, char *output, size_t output_size);




/* returns index of the first instance of ch in s starting at idx.
   returns length of s if char not found or 0 if s is NULL. */
int char_find(int idx, const char *s, char ch);

/* checks if a file exists. Returns true or false */
bool file_exists(const char *path);

/* Return true if address appears to be a valid ipv4 address. */
bool is_ip4_address(const char *address);

/* Return true if address roughly appears to be a valid ipv6 address.
 *
 * TODO: Improve this function (inet_pton behaves strangely with ipv6).
 * for now the only guarantee is that it won't return true if the
 * address is a domain or ipv4 address, and should only be used if you're
 * reasonably sure that the address is one of the three (ipv4, ipv6 or a domain).
 */
bool is_ip6_address(const char *address);

