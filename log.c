#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <time.h>
#include <syslog.h>
#include "log.h"

extern log_level;

void log_format (FILE *fp, const char* tag, const char* message, va_list args) {
	time_t now;
	time(&now);
	char * date =ctime(&now);   
	date[strlen(date) - 1] = '\0';  
	// fprintf(fp, "\n%s [%s] ", date, tag);  -- with date
	fprintf(fp, "\n[%s] ", tag);  
	vfprintf(fp, message, args);
}

void log_error(FILE *fp, const char* message, ...) {  
	va_list args;   
	va_start(args, message);    
	if (log_level < AS_LOG_ERROR) return;
	log_format(fp, "error", message, args);     
	va_end(args); 
}
void log_info(FILE *fp, const char* message, ...) {   
	va_list args;   
	va_start(args, message);    
	if (log_level < AS_LOG_INFO) return;
	log_format(fp, "info", message, args);  va_end(args); 
}
void log_debug(FILE *fp, const char* message, ...) {  
	va_list args;   
	va_start(args, message);    
	if (log_level < AS_LOG_DEBUG) return;
	log_format(fp, "debug", message, args);     
	va_end(args); 
}
