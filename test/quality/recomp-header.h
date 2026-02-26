/* Auto-generated header for decompiler output recompilation test */
#pragma once

/* Suppress all warnings */
#pragma clang diagnostic ignored "-Weverything"

/* Sized integer types */
typedef signed char int1;
typedef short int2;
typedef int int4;
typedef long long int8;
typedef unsigned char uint1;
typedef unsigned short uint2;
typedef unsigned int uint4;
typedef unsigned long long uint8;

/* Enhanced type names */
typedef signed char i8;
typedef short i16;
typedef int i32;
typedef long long i64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

/* Unknown types */
typedef unsigned char xunknown1;
typedef unsigned short xunknown2;
typedef unsigned int xunknown4;
typedef unsigned long long xunknown8;
typedef unsigned char unk1;
typedef unsigned short unk2;
typedef unsigned int unk4;
typedef unsigned long long unk8;

/* Float types */
typedef float float4;
typedef double float8;

/* Bool and true/false */
typedef unsigned char bool;
#ifndef true
#define true 1
#endif
#ifndef false
#define false 0
#endif
typedef unsigned char undefined;
typedef unsigned char undefined1;
typedef unsigned short undefined2;
typedef unsigned int undefined4;
typedef unsigned long long undefined8;
typedef long long longlong;
typedef unsigned long long ulonglong;
typedef unsigned long ulong;

/* CONCAT macros — concatenate two values into a wider type */
#define CONCAT11(a,b) ((uint2)(((uint2)(a)<<8)|(uint1)(b)))
#define CONCAT12(a,b) ((uint4)(((uint4)(uint1)(a)<<16)|(uint2)(b)))
#define CONCAT13(a,b) ((uint4)(((uint4)(uint1)(a)<<24)|(uint4)(b)&0xFFFFFF))
#define CONCAT14(a,b) ((uint8)(((uint8)(uint1)(a)<<32)|(uint4)(b)))
#define CONCAT15(a,b) ((uint8)(((uint8)(uint1)(a)<<40)|(uint8)(b)&0xFFFFFFFFFF))
#define CONCAT16(a,b) ((uint8)(((uint8)(uint1)(a)<<48)|(uint8)(b)&0xFFFFFFFFFFFF))
#define CONCAT17(a,b) ((uint8)(((uint8)(uint1)(a)<<56)|(uint8)(b)&0xFFFFFFFFFFFFFF))
#define CONCAT22(a,b) ((uint4)(((uint4)(uint2)(a)<<16)|(uint2)(b)))
#define CONCAT44(a,b) ((uint8)(((uint8)(uint4)(a)<<32)|(uint4)(b)))

/* ZEXT macro */
#define ZEXT816(a) ((unsigned __int128)(uint8)(a))

/* SUB macros — extract bytes from a value */
#define SUB41(a,b) ((uint1)((uint4)(a)>>(b*8)))
#define SUB42(a,b) ((uint2)((uint4)(a)>>(b*8)))
#define SUB81(a,b) ((uint1)((uint8)(a)>>(b*8)))
#define SUB82(a,b) ((uint2)((uint8)(a)>>(b*8)))
#define SUB84(a,b) ((uint4)((uint8)(a)>>(b*8)))

/* Forward declarations for common libc functions */
int _printf(const char *, ...);
int _fprintf(void *, const char *, ...);
int _sprintf(char *, const char *, ...);
int _snprintf(char *, unsigned long, const char *, ...);
void *_malloc(unsigned long);
void *_calloc(unsigned long, unsigned long);
void *_realloc(void *, unsigned long);
void _free(void *);
unsigned long _strlen(const char *);
char *_strcpy(char *, const char *);
char *_strncpy(char *, const char *, unsigned long);
int _strcmp(const char *, const char *);
int _strncmp(const char *, const char *, unsigned long);
void *_memcpy(void *, const void *, unsigned long);
void *_memset(void *, int, unsigned long);
int _memcmp(const void *, const void *, unsigned long);
void *_memmove(void *, const void *, unsigned long);
void _exit(int);
void __assert_rtn(const char *, const char *, int, const char *);
void ___stack_chk_fail(void);
int _atoi(const char *);
long _strtol(const char *, char **, int);
double _strtod(const char *, char **);
int ___maskrune(int, unsigned long);
int _abs(int);
double _sqrt(double);
double _pow(double, double);
double _fabs(double);
double _log(double);
double _exp(double);
void _qsort(void *, unsigned long, unsigned long, int (*)(const void *, const void *));
void *_bsearch(const void *, const void *, unsigned long, unsigned long, int (*)(const void *, const void *));
int _rand(void);
void _srand(unsigned int);
unsigned long _fwrite(const void *, unsigned long, unsigned long, void *);
unsigned long _fread(void *, unsigned long, unsigned long, void *);
void *_fopen(const char *, const char *);
int _fclose(void *);
int _puts(const char *);
int _putchar(int);

/* Catch-all: declare any undeclared identifier as int to avoid errors */
/* This is intentionally permissive for syntax-only checking */
