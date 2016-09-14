#ifndef LOG_H
#define LOG_H

void log_alert(FILE *fp, const char* message, ...); 
void log_error(FILE *fp, const char* message, ...); 
void log_info(FILE *fp, const char* message, ...); 
void log_debug(FILE *fp, const char* message, ...);

#define AS_LOG_DEBUG 3
#define AS_LOG_INFO  2
#define AS_LOG_ERROR 1

#endif /* LOG_H */
