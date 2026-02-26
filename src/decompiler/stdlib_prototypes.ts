/**
 * @file stdlib_prototypes.ts
 * @description Standard library function prototype database for enhanced display mode.
 *
 * When enhancedDisplay is enabled, injects proper function signatures for common
 * libc/POSIX functions so that return types and parameter types are correct in output.
 * Signatures extracted from macOS/POSIX man pages.
 */

import { type_metatype, Datatype } from './type.js';
import { PrototypePieces } from './fspec.js';

type Architecture = any;
type FuncProto = any;
type TypeFactory = any;

// ---------------------------------------------------------------------------
// Prototype descriptor types
// ---------------------------------------------------------------------------

const enum ParamKind {
  INT,       // int (4 bytes)
  UINT,      // unsigned int (4 bytes)
  LONG,      // long / ssize_t / off_t / time_t (pointer-sized, signed)
  SIZE_T,    // size_t (pointer-sized, unsigned)
  VOID_PTR,  // void* (also used for opaque struct pointers)
  CHAR_PTR,  // char* / const char*
  CHAR_PP,   // char**
  DOUBLE,    // double (8 bytes)
  VOID,      // void (only for return type)
}

interface StdlibProto {
  ret: ParamKind;
  params: Array<{ name: string; kind: ParamKind }>;
  isVarargs?: boolean;
  isNoReturn?: boolean;
}

// Shorthand for param entries
function p(name: string, kind: ParamKind): { name: string; kind: ParamKind } {
  return { name, kind };
}

const I = ParamKind.INT;
const U = ParamKind.UINT;
const L = ParamKind.LONG;
const Z = ParamKind.SIZE_T;
const VP = ParamKind.VOID_PTR;
const CP = ParamKind.CHAR_PTR;
const CPP = ParamKind.CHAR_PP;
const D = ParamKind.DOUBLE;
const V = ParamKind.VOID;

// ---------------------------------------------------------------------------
// The database, keyed by canonical name (no leading _)
// ---------------------------------------------------------------------------

const STDLIB_DB: Map<string, StdlibProto> = new Map([

  // =========================================================================
  // C Standard Library (stdio.h)
  // =========================================================================

  // printf family
  ['printf',   { ret: I, params: [p('format', CP)], isVarargs: true }],
  ['fprintf',  { ret: I, params: [p('stream', VP), p('format', CP)], isVarargs: true }],
  ['sprintf',  { ret: I, params: [p('str', CP), p('format', CP)], isVarargs: true }],
  ['snprintf', { ret: I, params: [p('str', CP), p('maxlen', Z), p('format', CP)], isVarargs: true }],
  ['vprintf',  { ret: I, params: [p('format', CP), p('ap', VP)] }],
  ['vfprintf', { ret: I, params: [p('stream', VP), p('format', CP), p('ap', VP)] }],
  ['vsprintf', { ret: I, params: [p('str', CP), p('format', CP), p('ap', VP)] }],
  ['vsnprintf',{ ret: I, params: [p('str', CP), p('maxlen', Z), p('format', CP), p('ap', VP)] }],

  // scanf family
  ['scanf',    { ret: I, params: [p('format', CP)], isVarargs: true }],
  ['fscanf',   { ret: I, params: [p('stream', VP), p('format', CP)], isVarargs: true }],
  ['sscanf',   { ret: I, params: [p('str', CP), p('format', CP)], isVarargs: true }],

  // Character/line I/O
  ['fgets',    { ret: CP, params: [p('str', CP), p('size', I), p('stream', VP)] }],
  ['fputs',    { ret: I, params: [p('s', CP), p('stream', VP)] }],
  ['fgetc',    { ret: I, params: [p('stream', VP)] }],
  ['fputc',    { ret: I, params: [p('c', I), p('stream', VP)] }],
  ['getc',     { ret: I, params: [p('stream', VP)] }],
  ['putc',     { ret: I, params: [p('c', I), p('stream', VP)] }],
  ['getchar',  { ret: I, params: [] }],
  ['putchar',  { ret: I, params: [p('c', I)] }],
  ['puts',     { ret: I, params: [p('s', CP)] }],
  ['ungetc',   { ret: I, params: [p('c', I), p('stream', VP)] }],

  // File operations
  ['fopen',    { ret: VP, params: [p('filename', CP), p('mode', CP)] }],
  ['fdopen',   { ret: VP, params: [p('fd', I), p('mode', CP)] }],
  ['freopen',  { ret: VP, params: [p('filename', CP), p('mode', CP), p('stream', VP)] }],
  ['fclose',   { ret: I, params: [p('stream', VP)] }],
  ['fflush',   { ret: I, params: [p('stream', VP)] }],
  ['fread',    { ret: Z, params: [p('ptr', VP), p('size', Z), p('nmemb', Z), p('stream', VP)] }],
  ['fwrite',   { ret: Z, params: [p('ptr', VP), p('size', Z), p('nmemb', Z), p('stream', VP)] }],

  // File positioning
  ['fseek',    { ret: I, params: [p('stream', VP), p('offset', L), p('whence', I)] }],
  ['ftell',    { ret: L, params: [p('stream', VP)] }],
  ['rewind',   { ret: V, params: [p('stream', VP)] }],

  // File status
  ['feof',     { ret: I, params: [p('stream', VP)] }],
  ['ferror',   { ret: I, params: [p('stream', VP)] }],
  ['clearerr', { ret: V, params: [p('stream', VP)] }],
  ['fileno',   { ret: I, params: [p('stream', VP)] }],

  // Error reporting
  ['perror',   { ret: V, params: [p('s', CP)] }],

  // =========================================================================
  // C Standard Library (stdlib.h) — memory
  // =========================================================================

  ['malloc',         { ret: VP, params: [p('size', Z)] }],
  ['calloc',         { ret: VP, params: [p('nmemb', Z), p('size', Z)] }],
  ['realloc',        { ret: VP, params: [p('ptr', VP), p('size', Z)] }],
  ['free',           { ret: V, params: [p('ptr', VP)] }],
  ['aligned_alloc',  { ret: VP, params: [p('alignment', Z), p('size', Z)] }],
  ['posix_memalign', { ret: I, params: [p('memptr', VP), p('alignment', Z), p('size', Z)] }],

  // =========================================================================
  // C Standard Library (string.h)
  // =========================================================================

  ['strlen',   { ret: Z, params: [p('s', CP)] }],
  ['strcpy',   { ret: CP, params: [p('dest', CP), p('src', CP)] }],
  ['strncpy',  { ret: CP, params: [p('dest', CP), p('src', CP), p('n', Z)] }],
  ['strcmp',    { ret: I, params: [p('s1', CP), p('s2', CP)] }],
  ['strncmp',  { ret: I, params: [p('s1', CP), p('s2', CP), p('n', Z)] }],
  ['strcat',   { ret: CP, params: [p('dest', CP), p('src', CP)] }],
  ['strncat',  { ret: CP, params: [p('dest', CP), p('src', CP), p('n', Z)] }],
  ['strchr',   { ret: CP, params: [p('s', CP), p('c', I)] }],
  ['strrchr',  { ret: CP, params: [p('s', CP), p('c', I)] }],
  ['strstr',   { ret: CP, params: [p('haystack', CP), p('needle', CP)] }],
  ['strpbrk',  { ret: CP, params: [p('s', CP), p('charset', CP)] }],
  ['strspn',   { ret: Z, params: [p('s', CP), p('charset', CP)] }],
  ['strcspn',  { ret: Z, params: [p('s', CP), p('charset', CP)] }],
  ['strtok',   { ret: CP, params: [p('str', CP), p('sep', CP)] }],
  ['strtok_r', { ret: CP, params: [p('str', CP), p('sep', CP), p('lasts', CPP)] }],
  ['strdup',   { ret: CP, params: [p('s1', CP)] }],
  ['strndup',  { ret: CP, params: [p('s1', CP), p('n', Z)] }],
  ['strsep',   { ret: CP, params: [p('stringp', CPP), p('delim', CP)] }],
  ['strerror', { ret: CP, params: [p('errnum', I)] }],
  ['strerror_r', { ret: I, params: [p('errnum', I), p('strerrbuf', CP), p('buflen', Z)] }],

  // BSD extensions
  ['strlcpy',  { ret: Z, params: [p('dst', CP), p('src', CP), p('dstsize', Z)] }],
  ['strlcat',  { ret: Z, params: [p('dst', CP), p('src', CP), p('dstsize', Z)] }],

  // Memory operations
  ['memcpy',   { ret: VP, params: [p('dest', VP), p('src', VP), p('n', Z)] }],
  ['memmove',  { ret: VP, params: [p('dest', VP), p('src', VP), p('n', Z)] }],
  ['memset',   { ret: VP, params: [p('s', VP), p('c', I), p('n', Z)] }],
  ['memcmp',   { ret: I, params: [p('s1', VP), p('s2', VP), p('n', Z)] }],
  ['memchr',   { ret: VP, params: [p('s', VP), p('c', I), p('n', Z)] }],
  ['bzero',    { ret: V, params: [p('s', VP), p('n', Z)] }],
  ['bcopy',    { ret: V, params: [p('src', VP), p('dst', VP), p('n', Z)] }],

  // =========================================================================
  // C Standard Library (stdlib.h) — conversion, random, utility
  // =========================================================================

  ['atoi',     { ret: I, params: [p('nptr', CP)] }],
  ['atol',     { ret: L, params: [p('nptr', CP)] }],
  ['atof',     { ret: D, params: [p('nptr', CP)] }],
  ['strtol',   { ret: L, params: [p('nptr', CP), p('endptr', CPP), p('base', I)] }],
  ['strtoul',  { ret: Z, params: [p('nptr', CP), p('endptr', CPP), p('base', I)] }],
  ['strtoll',  { ret: L, params: [p('nptr', CP), p('endptr', CPP), p('base', I)] }],
  ['strtoull', { ret: Z, params: [p('nptr', CP), p('endptr', CPP), p('base', I)] }],
  ['strtod',   { ret: D, params: [p('nptr', CP), p('endptr', CPP)] }],
  ['strtof',   { ret: D, params: [p('nptr', CP), p('endptr', CPP)] }],  // float, but use double
  ['abs',      { ret: I, params: [p('j', I)] }],
  ['labs',     { ret: L, params: [p('j', L)] }],
  ['rand',     { ret: I, params: [] }],
  ['srand',    { ret: V, params: [p('seed', U)] }],

  // Process control
  ['exit',     { ret: V, params: [p('status', I)], isNoReturn: true }],
  ['_exit',    { ret: V, params: [p('status', I)], isNoReturn: true }],
  ['_Exit',    { ret: V, params: [p('status', I)], isNoReturn: true }],
  ['abort',    { ret: V, params: [], isNoReturn: true }],
  ['atexit',   { ret: I, params: [p('function', VP)] }],

  // Environment
  ['getenv',   { ret: CP, params: [p('name', CP)] }],
  ['setenv',   { ret: I, params: [p('name', CP), p('value', CP), p('overwrite', I)] }],
  ['unsetenv', { ret: I, params: [p('name', CP)] }],
  ['putenv',   { ret: I, params: [p('string', CP)] }],

  // Sorting/searching
  ['qsort',    { ret: V, params: [p('base', VP), p('nmemb', Z), p('size', Z), p('compar', VP)] }],
  ['bsearch',  { ret: VP, params: [p('key', VP), p('base', VP), p('nmemb', Z), p('size', Z), p('compar', VP)] }],

  // Shell/process
  ['system',   { ret: I, params: [p('command', CP)] }],
  ['popen',    { ret: VP, params: [p('command', CP), p('mode', CP)] }],
  ['pclose',   { ret: I, params: [p('stream', VP)] }],
  ['realpath', { ret: CP, params: [p('file_name', CP), p('resolved_name', CP)] }],

  // =========================================================================
  // C Standard Library (math.h)
  // =========================================================================

  ['sqrt',   { ret: D, params: [p('x', D)] }],
  ['sqrtf',  { ret: D, params: [p('x', D)] }],
  ['pow',    { ret: D, params: [p('base', D), p('exp', D)] }],
  ['powf',   { ret: D, params: [p('base', D), p('exp', D)] }],
  ['fabs',   { ret: D, params: [p('x', D)] }],
  ['fabsf',  { ret: D, params: [p('x', D)] }],
  ['log',    { ret: D, params: [p('x', D)] }],
  ['logf',   { ret: D, params: [p('x', D)] }],
  ['log2',   { ret: D, params: [p('x', D)] }],
  ['log10',  { ret: D, params: [p('x', D)] }],
  ['exp',    { ret: D, params: [p('x', D)] }],
  ['expf',   { ret: D, params: [p('x', D)] }],
  ['exp2',   { ret: D, params: [p('x', D)] }],
  ['ceil',   { ret: D, params: [p('x', D)] }],
  ['ceilf',  { ret: D, params: [p('x', D)] }],
  ['floor',  { ret: D, params: [p('x', D)] }],
  ['floorf', { ret: D, params: [p('x', D)] }],
  ['round',  { ret: D, params: [p('x', D)] }],
  ['roundf', { ret: D, params: [p('x', D)] }],
  ['trunc',  { ret: D, params: [p('x', D)] }],
  ['truncf', { ret: D, params: [p('x', D)] }],
  ['fmod',   { ret: D, params: [p('x', D), p('y', D)] }],
  ['fmodf',  { ret: D, params: [p('x', D), p('y', D)] }],
  ['sin',    { ret: D, params: [p('x', D)] }],
  ['cos',    { ret: D, params: [p('x', D)] }],
  ['tan',    { ret: D, params: [p('x', D)] }],
  ['asin',   { ret: D, params: [p('x', D)] }],
  ['acos',   { ret: D, params: [p('x', D)] }],
  ['atan',   { ret: D, params: [p('x', D)] }],
  ['atan2',  { ret: D, params: [p('y', D), p('x', D)] }],
  ['sinh',   { ret: D, params: [p('x', D)] }],
  ['cosh',   { ret: D, params: [p('x', D)] }],
  ['tanh',   { ret: D, params: [p('x', D)] }],
  ['lround', { ret: L, params: [p('x', D)] }],
  ['lrint',  { ret: L, params: [p('x', D)] }],

  // =========================================================================
  // C Standard Library (ctype.h)
  // =========================================================================

  ['isalpha',  { ret: I, params: [p('c', I)] }],
  ['isdigit',  { ret: I, params: [p('c', I)] }],
  ['isalnum',  { ret: I, params: [p('c', I)] }],
  ['isspace',  { ret: I, params: [p('c', I)] }],
  ['isupper',  { ret: I, params: [p('c', I)] }],
  ['islower',  { ret: I, params: [p('c', I)] }],
  ['isprint',  { ret: I, params: [p('c', I)] }],
  ['ispunct',  { ret: I, params: [p('c', I)] }],
  ['iscntrl',  { ret: I, params: [p('c', I)] }],
  ['isxdigit', { ret: I, params: [p('c', I)] }],
  ['isascii',  { ret: I, params: [p('c', I)] }],
  ['toupper',  { ret: I, params: [p('c', I)] }],
  ['tolower',  { ret: I, params: [p('c', I)] }],

  // =========================================================================
  // POSIX — File I/O (unistd.h, fcntl.h)
  // =========================================================================

  ['open',     { ret: I, params: [p('path', CP), p('oflag', I)], isVarargs: true }],
  ['openat',   { ret: I, params: [p('fd', I), p('path', CP), p('oflag', I)], isVarargs: true }],
  ['close',    { ret: I, params: [p('fildes', I)] }],
  ['read',     { ret: L, params: [p('fildes', I), p('buf', VP), p('nbyte', Z)] }],
  ['write',    { ret: L, params: [p('fildes', I), p('buf', VP), p('nbyte', Z)] }],
  ['pread',    { ret: L, params: [p('d', I), p('buf', VP), p('nbyte', Z), p('offset', L)] }],
  ['pwrite',   { ret: L, params: [p('fildes', I), p('buf', VP), p('nbyte', Z), p('offset', L)] }],
  ['lseek',    { ret: L, params: [p('fildes', I), p('offset', L), p('whence', I)] }],
  ['dup',      { ret: I, params: [p('fildes', I)] }],
  ['dup2',     { ret: I, params: [p('fildes', I), p('fildes2', I)] }],
  ['pipe',     { ret: I, params: [p('fildes', VP)] }],  // int[2] → void*
  ['fcntl',    { ret: I, params: [p('fildes', I), p('cmd', I)], isVarargs: true }],
  ['ioctl',    { ret: I, params: [p('fildes', I), p('request', L)], isVarargs: true }],
  ['fsync',    { ret: I, params: [p('fildes', I)] }],
  ['ftruncate',{ ret: I, params: [p('fildes', I), p('length', L)] }],
  ['truncate', { ret: I, params: [p('path', CP), p('length', L)] }],
  ['isatty',   { ret: I, params: [p('fildes', I)] }],

  // =========================================================================
  // POSIX — File system (sys/stat.h, dirent.h)
  // =========================================================================

  ['stat',     { ret: I, params: [p('path', CP), p('buf', VP)] }],
  ['fstat',    { ret: I, params: [p('fildes', I), p('buf', VP)] }],
  ['lstat',    { ret: I, params: [p('path', CP), p('buf', VP)] }],
  ['fstatat',  { ret: I, params: [p('fd', I), p('path', CP), p('buf', VP), p('flag', I)] }],
  ['chmod',    { ret: I, params: [p('path', CP), p('mode', U)] }],
  ['fchmod',   { ret: I, params: [p('fildes', I), p('mode', U)] }],
  ['chown',    { ret: I, params: [p('path', CP), p('owner', U), p('group', U)] }],
  ['fchown',   { ret: I, params: [p('fildes', I), p('owner', U), p('group', U)] }],
  ['mkdir',    { ret: I, params: [p('path', CP), p('mode', U)] }],
  ['rmdir',    { ret: I, params: [p('path', CP)] }],
  ['unlink',   { ret: I, params: [p('path', CP)] }],
  ['rename',   { ret: I, params: [p('old', CP), p('new_', CP)] }],
  ['remove',   { ret: I, params: [p('path', CP)] }],
  ['link',     { ret: I, params: [p('path1', CP), p('path2', CP)] }],
  ['symlink',  { ret: I, params: [p('path1', CP), p('path2', CP)] }],
  ['readlink', { ret: L, params: [p('path', CP), p('buf', CP), p('bufsiz', Z)] }],
  ['access',   { ret: I, params: [p('path', CP), p('mode', I)] }],
  ['chdir',    { ret: I, params: [p('path', CP)] }],
  ['fchdir',   { ret: I, params: [p('fildes', I)] }],
  ['getcwd',   { ret: CP, params: [p('buf', CP), p('size', Z)] }],
  ['umask',    { ret: U, params: [p('cmask', U)] }],

  // Directory operations
  ['opendir',  { ret: VP, params: [p('filename', CP)] }],
  ['readdir',  { ret: VP, params: [p('dirp', VP)] }],
  ['closedir', { ret: I, params: [p('dirp', VP)] }],
  ['rewinddir',{ ret: V, params: [p('dirp', VP)] }],

  // =========================================================================
  // POSIX — Process (unistd.h, sys/wait.h)
  // =========================================================================

  ['fork',     { ret: I, params: [] }],
  ['getpid',   { ret: I, params: [] }],
  ['getppid',  { ret: I, params: [] }],
  ['getuid',   { ret: U, params: [] }],
  ['geteuid',  { ret: U, params: [] }],
  ['getgid',   { ret: U, params: [] }],
  ['getegid',  { ret: U, params: [] }],
  ['setsid',   { ret: I, params: [] }],
  ['setuid',   { ret: I, params: [p('uid', U)] }],
  ['setgid',   { ret: I, params: [p('gid', U)] }],
  ['execve',   { ret: I, params: [p('path', CP), p('argv', VP), p('envp', VP)] }],
  ['execv',    { ret: I, params: [p('path', CP), p('argv', VP)] }],
  ['execvp',   { ret: I, params: [p('file', CP), p('argv', VP)] }],
  ['wait',     { ret: I, params: [p('stat_loc', VP)] }],
  ['waitpid',  { ret: I, params: [p('pid', I), p('stat_loc', VP), p('options', I)] }],
  ['kill',     { ret: I, params: [p('pid', I), p('sig', I)] }],
  ['raise',    { ret: I, params: [p('sig', I)] }],
  ['sysconf',  { ret: L, params: [p('name', I)] }],

  // =========================================================================
  // POSIX — Signals (signal.h)
  // =========================================================================

  ['signal',      { ret: VP, params: [p('sig', I), p('func', VP)] }],
  ['sigaction',   { ret: I, params: [p('sig', I), p('act', VP), p('oact', VP)] }],
  ['sigemptyset', { ret: I, params: [p('set', VP)] }],
  ['sigfillset',  { ret: I, params: [p('set', VP)] }],
  ['sigaddset',   { ret: I, params: [p('set', VP), p('signo', I)] }],
  ['sigdelset',   { ret: I, params: [p('set', VP), p('signo', I)] }],
  ['sigismember', { ret: I, params: [p('set', VP), p('signo', I)] }],
  ['sigprocmask', { ret: I, params: [p('how', I), p('set', VP), p('oset', VP)] }],
  ['sigwait',     { ret: I, params: [p('set', VP), p('sig', VP)] }],

  // =========================================================================
  // POSIX — Memory mapping (sys/mman.h)
  // =========================================================================

  ['mmap',     { ret: VP, params: [p('addr', VP), p('len', Z), p('prot', I), p('flags', I), p('fd', I), p('offset', L)] }],
  ['munmap',   { ret: I, params: [p('addr', VP), p('len', Z)] }],
  ['mprotect', { ret: I, params: [p('addr', VP), p('len', Z), p('prot', I)] }],
  ['msync',    { ret: I, params: [p('addr', VP), p('len', Z), p('flags', I)] }],
  ['mlock',    { ret: I, params: [p('addr', VP), p('len', Z)] }],
  ['munlock',  { ret: I, params: [p('addr', VP), p('len', Z)] }],
  ['madvise',  { ret: I, params: [p('addr', VP), p('len', Z), p('advice', I)] }],
  ['shm_open', { ret: I, params: [p('name', CP), p('oflag', I)], isVarargs: true }],
  ['shm_unlink', { ret: I, params: [p('name', CP)] }],

  // =========================================================================
  // POSIX — Sockets (sys/socket.h, netinet/in.h, arpa/inet.h)
  // =========================================================================

  ['socket',     { ret: I, params: [p('domain', I), p('type', I), p('protocol', I)] }],
  ['bind',       { ret: I, params: [p('socket', I), p('address', VP), p('address_len', U)] }],
  ['listen',     { ret: I, params: [p('socket', I), p('backlog', I)] }],
  ['accept',     { ret: I, params: [p('socket', I), p('address', VP), p('address_len', VP)] }],
  ['connect',    { ret: I, params: [p('socket', I), p('address', VP), p('address_len', U)] }],
  ['send',       { ret: L, params: [p('socket', I), p('buffer', VP), p('length', Z), p('flags', I)] }],
  ['recv',       { ret: L, params: [p('socket', I), p('buffer', VP), p('length', Z), p('flags', I)] }],
  ['sendto',     { ret: L, params: [p('socket', I), p('buffer', VP), p('length', Z), p('flags', I), p('dest_addr', VP), p('dest_len', U)] }],
  ['recvfrom',   { ret: L, params: [p('socket', I), p('buffer', VP), p('length', Z), p('flags', I), p('address', VP), p('address_len', VP)] }],
  ['setsockopt', { ret: I, params: [p('socket', I), p('level', I), p('option_name', I), p('option_value', VP), p('option_len', U)] }],
  ['getsockopt', { ret: I, params: [p('socket', I), p('level', I), p('option_name', I), p('option_value', VP), p('option_len', VP)] }],
  ['shutdown',   { ret: I, params: [p('socket', I), p('how', I)] }],
  ['getaddrinfo',  { ret: I, params: [p('hostname', CP), p('servname', CP), p('hints', VP), p('res', VP)] }],
  ['freeaddrinfo', { ret: V, params: [p('ai', VP)] }],
  ['getnameinfo',  { ret: I, params: [p('sa', VP), p('salen', U), p('host', CP), p('hostlen', U), p('serv', CP), p('servlen', U), p('flags', I)] }],
  ['inet_pton',    { ret: I, params: [p('af', I), p('src', CP), p('dst', VP)] }],
  ['inet_ntop',    { ret: CP, params: [p('af', I), p('src', VP), p('dst', CP), p('size', U)] }],
  ['inet_addr',    { ret: U, params: [p('cp', CP)] }],
  ['htons',        { ret: U, params: [p('hostshort', U)] }],  // uint16_t but simplify
  ['htonl',        { ret: U, params: [p('hostlong', U)] }],
  ['ntohs',        { ret: U, params: [p('netshort', U)] }],
  ['ntohl',        { ret: U, params: [p('netlong', U)] }],

  // =========================================================================
  // POSIX — select/poll
  // =========================================================================

  ['select',   { ret: I, params: [p('nfds', I), p('readfds', VP), p('writefds', VP), p('errorfds', VP), p('timeout', VP)] }],
  ['poll',     { ret: I, params: [p('fds', VP), p('nfds', U), p('timeout', I)] }],

  // =========================================================================
  // POSIX — pthreads (pthread.h)
  // =========================================================================

  ['pthread_create',        { ret: I, params: [p('thread', VP), p('attr', VP), p('start_routine', VP), p('arg', VP)] }],
  ['pthread_join',          { ret: I, params: [p('thread', L), p('value_ptr', VP)] }],  // pthread_t is unsigned long
  ['pthread_exit',          { ret: V, params: [p('value_ptr', VP)], isNoReturn: true }],
  ['pthread_detach',        { ret: I, params: [p('thread', L)] }],
  ['pthread_self',          { ret: L, params: [] }],
  ['pthread_equal',         { ret: I, params: [p('t1', L), p('t2', L)] }],
  ['pthread_mutex_init',    { ret: I, params: [p('mutex', VP), p('attr', VP)] }],
  ['pthread_mutex_destroy', { ret: I, params: [p('mutex', VP)] }],
  ['pthread_mutex_lock',    { ret: I, params: [p('mutex', VP)] }],
  ['pthread_mutex_trylock', { ret: I, params: [p('mutex', VP)] }],
  ['pthread_mutex_unlock',  { ret: I, params: [p('mutex', VP)] }],
  ['pthread_cond_init',     { ret: I, params: [p('cond', VP), p('attr', VP)] }],
  ['pthread_cond_destroy',  { ret: I, params: [p('cond', VP)] }],
  ['pthread_cond_wait',     { ret: I, params: [p('cond', VP), p('mutex', VP)] }],
  ['pthread_cond_signal',   { ret: I, params: [p('cond', VP)] }],
  ['pthread_cond_broadcast',{ ret: I, params: [p('cond', VP)] }],
  ['pthread_rwlock_init',     { ret: I, params: [p('rwlock', VP), p('attr', VP)] }],
  ['pthread_rwlock_destroy',  { ret: I, params: [p('rwlock', VP)] }],
  ['pthread_rwlock_rdlock',   { ret: I, params: [p('rwlock', VP)] }],
  ['pthread_rwlock_wrlock',   { ret: I, params: [p('rwlock', VP)] }],
  ['pthread_rwlock_unlock',   { ret: I, params: [p('rwlock', VP)] }],
  ['pthread_once',            { ret: I, params: [p('once_control', VP), p('init_routine', VP)] }],
  ['pthread_key_create',      { ret: I, params: [p('key', VP), p('destructor', VP)] }],
  ['pthread_key_delete',      { ret: I, params: [p('key', U)] }],
  ['pthread_setspecific',     { ret: I, params: [p('key', U), p('value', VP)] }],
  ['pthread_getspecific',     { ret: VP, params: [p('key', U)] }],

  // =========================================================================
  // POSIX — Time (time.h, sys/time.h)
  // =========================================================================

  ['time',          { ret: L, params: [p('tloc', VP)] }],
  ['clock',         { ret: L, params: [] }],
  ['clock_gettime', { ret: I, params: [p('clock_id', I), p('tp', VP)] }],
  ['clock_settime', { ret: I, params: [p('clock_id', I), p('tp', VP)] }],
  ['clock_getres',  { ret: I, params: [p('clock_id', I), p('tp', VP)] }],
  ['gettimeofday',  { ret: I, params: [p('tp', VP), p('tzp', VP)] }],
  ['settimeofday',  { ret: I, params: [p('tp', VP), p('tzp', VP)] }],
  ['localtime',     { ret: VP, params: [p('clock', VP)] }],
  ['localtime_r',   { ret: VP, params: [p('clock', VP), p('result', VP)] }],
  ['gmtime',        { ret: VP, params: [p('clock', VP)] }],
  ['gmtime_r',      { ret: VP, params: [p('clock', VP), p('result', VP)] }],
  ['mktime',        { ret: L, params: [p('timeptr', VP)] }],
  ['difftime',      { ret: D, params: [p('time1', L), p('time0', L)] }],
  ['strftime',      { ret: Z, params: [p('s', CP), p('maxsize', Z), p('format', CP), p('timeptr', VP)] }],
  ['asctime',       { ret: CP, params: [p('timeptr', VP)] }],
  ['asctime_r',     { ret: CP, params: [p('timeptr', VP), p('buf', CP)] }],
  ['ctime',         { ret: CP, params: [p('clock', VP)] }],
  ['ctime_r',       { ret: CP, params: [p('clock', VP), p('buf', CP)] }],
  ['nanosleep',     { ret: I, params: [p('rqtp', VP), p('rmtp', VP)] }],
  ['sleep',         { ret: U, params: [p('seconds', U)] }],
  ['usleep',        { ret: I, params: [p('useconds', U)] }],
  ['alarm',         { ret: U, params: [p('seconds', U)] }],
  ['pause',         { ret: I, params: [] }],

  // =========================================================================
  // POSIX — Dynamic linking (dlfcn.h)
  // =========================================================================

  ['dlopen',  { ret: VP, params: [p('path', CP), p('mode', I)] }],
  ['dlclose', { ret: I, params: [p('handle', VP)] }],
  ['dlsym',   { ret: VP, params: [p('handle', VP), p('symbol', CP)] }],
  ['dlerror', { ret: CP, params: [] }],

  // =========================================================================
  // POSIX — Non-local jumps (setjmp.h)
  // =========================================================================

  ['setjmp',     { ret: I, params: [p('env', VP)] }],
  ['longjmp',    { ret: V, params: [p('env', VP), p('val', I)] }],
  ['sigsetjmp',  { ret: I, params: [p('env', VP), p('savemask', I)] }],
  ['siglongjmp', { ret: V, params: [p('env', VP), p('val', I)] }],

  // =========================================================================
  // POSIX — Miscellaneous
  // =========================================================================

  ['getopt',   { ret: I, params: [p('argc', I), p('argv', VP), p('optstring', CP)] }],
  ['basename', { ret: CP, params: [p('path', CP)] }],
  ['dirname',  { ret: CP, params: [p('path', CP)] }],

  // =========================================================================
  // Platform — stack protector
  // =========================================================================

  ['_stack_chk_fail', { ret: V, params: [], isNoReturn: true }],
]);

// ---------------------------------------------------------------------------
// Canonical name resolution
// ---------------------------------------------------------------------------

/**
 * Strip leading underscores from a function name to get the canonical form.
 * Mach-O symbols have a single leading `_` (e.g. `_printf` → `printf`).
 * `___stack_chk_fail` → `__stack_chk_fail` → `_stack_chk_fail`.
 */
function canonicalize(name: string): string {
  if (name.startsWith('_')) {
    return name.substring(1);
  }
  return name;
}

// ---------------------------------------------------------------------------
// Type construction helper
// ---------------------------------------------------------------------------

function buildType(kind: ParamKind, types: TypeFactory, ptrSize: number, wordSize: number): Datatype {
  switch (kind) {
    case ParamKind.INT:
      return types.getBase(4, type_metatype.TYPE_INT);
    case ParamKind.UINT:
      return types.getBase(4, type_metatype.TYPE_UINT);
    case ParamKind.LONG:
      return types.getBase(ptrSize, type_metatype.TYPE_INT);
    case ParamKind.SIZE_T:
      return types.getBase(ptrSize, type_metatype.TYPE_UINT);
    case ParamKind.VOID:
      return types.getTypeVoid();
    case ParamKind.VOID_PTR:
      return types.getTypePointer(ptrSize, types.getTypeVoid(), wordSize);
    case ParamKind.CHAR_PTR:
      return types.getTypePointer(ptrSize, types.getTypeChar(1), wordSize);
    case ParamKind.CHAR_PP: {
      const charPtr = types.getTypePointer(ptrSize, types.getTypeChar(1), wordSize);
      return types.getTypePointer(ptrSize, charPtr, wordSize);
    }
    case ParamKind.DOUBLE:
      return types.getBase(8, type_metatype.TYPE_FLOAT);
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Apply a standard library prototype to the given FuncProto if the function
 * name matches a known stdlib function.
 *
 * @returns true if a prototype was applied, false if the name was not found.
 */
export function applyStdlibPrototype(
  funcProto: FuncProto,
  funcName: string,
  arch: Architecture,
): boolean {
  const canonical = canonicalize(funcName);
  const entry = STDLIB_DB.get(canonical);
  if (entry === undefined) return false;

  const types = arch.types as TypeFactory;
  const dataSpace = arch.getDefaultDataSpace();
  const ptrSize: number = dataSpace.getAddrSize();
  const wordSize: number = dataSpace.getWordSize();

  const pieces = new PrototypePieces();
  pieces.model = arch.evalfp_called ?? arch.defaultfp;
  pieces.name = funcName;
  pieces.outtype = buildType(entry.ret, types, ptrSize, wordSize);

  for (const p of entry.params) {
    pieces.intypes.push(buildType(p.kind, types, ptrSize, wordSize));
    pieces.innames.push(p.name);
  }

  if (entry.isVarargs) {
    pieces.firstVarArgSlot = entry.params.length;
  }

  funcProto.setPieces(pieces);
  return true;
}
