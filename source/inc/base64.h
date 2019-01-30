#ifndef BASE64_H  
#define BASE64_H  
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int base64_encode(char *in_str, int in_len, char *out_str);
int base64_decode(char *in_str, char *out_str); 
#endif  
