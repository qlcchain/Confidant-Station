#ifndef _LINUX_CRC32_H
#define _LINUX_CRC32_H

#include <linux/types.h>

unsigned int crc32(unsigned int crc, unsigned char * buffer, unsigned int size);
unsigned short crc16(unsigned char *message, unsigned int len);
void init_crc_table(void);
unsigned short gen_crc16(const unsigned char *data, unsigned short size);
unsigned short CalculateCRC16(unsigned char* pchMsg, unsigned short wDataLen);
extern unsigned int crc_table[256];

#endif 
