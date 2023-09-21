#ifndef NGX_HTTP_LUA_OPENTELEMETRY_H
#define NGX_HTTP_LUA_OPENTELEMETRY_H

#include "ngx_http_opentelemetry_module.h"
#include "ngx_http_lua_common.h"
#include <unistd.h>
#include <stdint.h>
#include <stdbool.h>


void ngx_http_lua_inject_opentelemetry_api(lua_State *L);

void ngx_http_lua_opentelemetry_span_start_helper(void *data, const char *operation_name, size_t operation_name_len);
void ngx_http_lua_opentelemetry_span_finish_helper(void *data);
bool ngx_http_lua_opentelemetry_span_debug_helper(void *data);
void ngx_http_lua_opentelemetry_span_add_event_helper(void *data, const opentelemetry_string *name, const opentelemetry_attribute *attributes, size_t nattributes);

#endif /* NGX_HTTP_LUA_OPENTELEMETRY_H */

