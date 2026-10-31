#ifndef VERGEAUTH_PROXY_H
#define VERGEAUTH_PROXY_H

#include "config.h"

void log_message(const char *format, ...);
/* ready_fd is notified after the listener and all signal handlers are ready. */
int proxy_run(struct config *config, const char *path, int ready_fd);

#endif
