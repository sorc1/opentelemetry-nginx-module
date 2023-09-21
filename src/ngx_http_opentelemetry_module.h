#ifndef _NGX_HTTP_OPENTELEMETRY_MODULE_H_INCLUDED_
#define _NGX_HTTP_OPENTELEMETRY_MODULE_H_INCLUDED_

#include <nginx.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <stdbool.h>
#include <opentelemetry-c/common.h>

ngx_int_t ngx_http_opentelemetry_is_enabled(ngx_http_request_t *r);
opentelemetry_span *ngx_http_opentelemetry_get_request_span(ngx_http_request_t *r);
opentelemetry_span *ngx_http_opentelemetry_span_start(ngx_http_request_t *r, opentelemetry_span *parent, const char *operation_name, size_t operation_name_len);
int ngx_http_opentelemetry_span_debug(ngx_http_request_t *r, opentelemetry_span *span);
int ngx_http_opentelemetry_span_headers_get(ngx_http_request_t *r, opentelemetry_span *span, opentelemetry_header_each header_each, void *header_each_arg);
opentelemetry_span *ngx_http_opentelemetry_span_start_headers(ngx_http_request_t *r, const char *operation_name, size_t operation_name_len, opentelemetry_header_value header_value, void *header_value_arg);
void ngx_http_opentelemetry_span_finish(ngx_http_request_t *r, opentelemetry_span *span);

#endif
