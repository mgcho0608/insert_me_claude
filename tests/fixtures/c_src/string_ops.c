/*
 * string_ops.c — fixture file for insert_me seeder tests.
 * Contains dangerous string-handling and format-string patterns.
 * Intentionally realistic; not a security reference.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define MAX_NAME 64
#define LOG_BUF  256

/* Unsafe strcpy — destination may be too small */
void greet_user(const char *name)
{
    char buf[MAX_NAME];
    strcpy(buf, name);              /* CWE-120: no bounds check */
    printf("Hello, %s\n", buf);
}

/* sprintf without size limit */
void format_log(const char *event, const char *detail)
{
    char line[LOG_BUF];
    sprintf(line, "[EVENT] %s: %s", event, detail);   /* CWE-120 */
    puts(line);
}

/* Dangerous: format string directly from caller */
void debug_raw(const char *fmt)
{
    printf(fmt);                    /* CWE-134: format string from user */
}

/* Dangerous: fprintf format from caller */
void log_raw(FILE *fp, const char *fmt)
{
    fprintf(fp, fmt);               /* CWE-134 */
}

/* Concatenation without bounds checks */
void build_path(char *dst, const char *dir, const char *name)
{
    strcpy(dst, dir);
    strcat(dst, "/");               /* CWE-120: strcat without size check */
    strcat(dst, name);
}

/* Reads input without bound — classic gets() vulnerability */
void read_line(char *out)
{
    gets(out);                      /* CWE-242: use of gets() */
}

/* Safe variant for comparison (should NOT be selected as a target) */
void safe_format(char *out, size_t outsz, const char *fmt, const char *val)
{
    snprintf(out, outsz, fmt, val);
}
