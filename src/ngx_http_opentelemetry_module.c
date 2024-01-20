#include "ngx_http_opentelemetry_module.h"
#include <opentelemetry-c/exporter_jaeger_trace.h>
#include <opentelemetry-c/exporter_otlp_http.h>

#define OPENTELEMETRY_HEADER_VARIABLE_PREFIX "opentelemetry_header_"

#define NGX_HTTP_OPENTELEMETRY_EXPORTER_JAEGER_OPTION_FORMAT_DEFAULT OPENTELEMETRY_C_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT
#define NGX_HTTP_OPENTELEMETRY_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT_SERVER_PORT_DEFAULT 6831

#define NGX_HTTP_OPENTELEMETRY_EXPORTER_OTLP_HTTP_OPTION_CONTENT_TYPE_DEFAULT OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_CONTENT_TYPE_BINARY
#define NGX_HTTP_OPENTELEMETRY_EXPORTER_OTLP_HTTP_OPTION_JSON_BYTES_MAPPING_DEFAULT OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_JSON_BMAPPING_KHEXID

#define NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_DEFAULT NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH
#define NGX_HTTP_OPENTELEMETRY_PROCESSOR_BATCH_OPTION_MAX_QUEUE_SIZE_DEFAULT 2048
#define NGX_HTTP_OPENTELEMETRY_PROCESSOR_BATCH_OPTION_SCHEDULE_DELAY_MILLIS_DEFAULT 5000
#define NGX_HTTP_OPENTELEMETRY_PROCESSOR_BATCH_OPTION_MAX_EXPORT_BATCH_SIZE_DEFAULT 512

static const opentelemetry_string ngx_http_opentelemetry_request_name = OPENTELEMETRY_CSTR("request");
static const opentelemetry_string ngx_http_opentelemetry_request_header_attribute_prefix = OPENTELEMETRY_CSTR("http.request.header.");

typedef enum ngx_http_opentelemetry_exporter_type {
    NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_NONE = 0,
    NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_JAEGER,
    NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_OTLP_HTTP,
} ngx_http_opentelemetry_exporter_type;

typedef enum ngx_http_opentelemetry_processor_type {
    NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_NONE = 0,
    NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_SIMPLE,
    NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH,
} ngx_http_opentelemetry_processor_type;

typedef struct {
    ngx_http_opentelemetry_exporter_type exporter_type;
    ngx_http_opentelemetry_processor_type processor_type;
    union {
        opentelemetry_exporter_jaeger_options jaeger;
        opentelemetry_exporter_otlp_http_options otlp_http;
    } exporter_options;
    union {
        opentelemetry_processor_batch_options batch_options;
    } processor_options;
    ngx_str_t tracestate_debug_key;
    ngx_str_t tracestate_debug_value;
    ngx_str_t service_name;
    ngx_flag_t limit_span_size;
} ngx_http_opentelemetry_main_conf_t;

typedef struct {
    ngx_array_t              *from;     /* array of ngx_cidr_t */
    ngx_array_t              *parent_from; /* array of ngx_cidr_t */
    ngx_http_complex_value_t *variable;
    double                    sample;
    ngx_flag_t                parent;
} ngx_http_opentelemetry_loc_conf_t;

typedef struct {
    unsigned tracing_level;
    opentelemetry_span *request_span;
} ngx_http_opentelemetry_ctx_t;

static ngx_int_t ngx_http_opentelemetry_init_process(ngx_cycle_t *cycle);
static void ngx_http_opentelemetry_exit_process(ngx_cycle_t *cycle);
static ngx_int_t ngx_http_opentelemetry_preconf(ngx_conf_t *cf);
static ngx_int_t ngx_http_opentelemetry_init(ngx_conf_t *cf);
static void *ngx_http_opentelemetry_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_opentelemetry_init_main_conf(ngx_conf_t *cf, void *conf);
static void *ngx_http_opentelemetry_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_opentelemetry_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char *ngx_http_set_opentelemetry_jaeger_exporter_options(ngx_conf_t *cf, opentelemetry_exporter_jaeger_options *jaeger_options);
static char *ngx_http_set_opentelemetry_otlp_http_exporter_options(ngx_conf_t *cf, opentelemetry_exporter_otlp_http_options *otlp_http_options);
static char *ngx_http_set_opentelemetry_batch_processor_options(ngx_conf_t *cf, opentelemetry_processor_batch_options *batch_options);
static char *ngx_http_set_opentelemetry_exporter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_opentelemetry_tracestate_debug(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_opentelemetry_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_opentelemetry_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_http_set_opentelemetry_sample(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_opentelemetry_header_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);

static ngx_http_variable_t ngx_http_opentelemetry_vars[] = {
    { ngx_string(OPENTELEMETRY_HEADER_VARIABLE_PREFIX),
      NULL,
      ngx_http_opentelemetry_header_variable,
      0,
      NGX_HTTP_VAR_PREFIX,
      0 },

      ngx_http_null_variable
};

static ngx_command_t ngx_http_opentelemetry_commands[] = {

    { ngx_string("opentelemetry_service_name"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_main_conf_t, service_name),
      NULL },

    { ngx_string("opentelemetry_exporter"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2|NGX_CONF_TAKE3|NGX_CONF_TAKE4,
      ngx_http_set_opentelemetry_exporter,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("opentelemetry_tracestate_debug"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2,
      ngx_http_set_opentelemetry_tracestate_debug,
      NGX_HTTP_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("opentelemetry_limit_span_size"),
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_MAIN_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_main_conf_t, limit_span_size),
      NULL },

    { ngx_string("opentelemetry_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, from),
      NULL },

    { ngx_string("opentelemetry"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("opentelemetry_sample"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_sample,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("opentelemetry_parent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, parent),
      NULL },

    { ngx_string("opentelemetry_parent_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, parent_from),
      NULL },

      ngx_null_command
};

static ngx_http_module_t ngx_http_opentelemetry_module_ctx = {
    ngx_http_opentelemetry_preconf,        /* preconfiguration */
    ngx_http_opentelemetry_init,           /* postconfiguration */

    ngx_http_opentelemetry_create_main_conf,/* create main configuration */
    ngx_http_opentelemetry_init_main_conf,  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_opentelemetry_create_loc_conf,/* create location configuration */
    ngx_http_opentelemetry_merge_loc_conf, /* merge location configuration */
};


ngx_module_t ngx_http_opentelemetry_module = {
    NGX_MODULE_V1,
    &ngx_http_opentelemetry_module_ctx,    /* module context */
    ngx_http_opentelemetry_commands,       /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_opentelemetry_init_process,   /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    ngx_http_opentelemetry_exit_process,   /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static opentelemetry_tracer *tracer;
static opentelemetry_provider *provider;
static bool sampler_debug;

static bool ngx_http_opentelemetry_sampler(opentelemetry_sampling_result *result, void *arg)
{
    ngx_cycle_t *cycle = arg;
    ngx_http_opentelemetry_main_conf_t *omcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_opentelemetry_module);
    opentelemetry_trace_state *ts = NULL;

    result->decision = OPENTELEMETRY_SAMPLING_DESISION_RECORD_AND_SAMPLE;
    if (sampler_debug && (ts = opentelemetry_trace_state_create()) != NULL) {
        opentelemetry_trace_state *ts2;

        ts2 = opentelemetry_trace_state_set(ts, (char*)omcf->tracestate_debug_key.data, omcf->tracestate_debug_key.len,
            (char*)omcf->tracestate_debug_value.data, omcf->tracestate_debug_value.len);
        opentelemetry_trace_state_destroy(ts);
        ts = ts2;
    }
    result->ts = ts;
    return true;
}

static ngx_int_t
ngx_http_opentelemetry_init_process(ngx_cycle_t *cycle)
{
    ngx_http_opentelemetry_main_conf_t *omcf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_opentelemetry_module);
    opentelemetry_exporter *exporter;

    switch (omcf->exporter_type) {
    case NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_NONE:
        return NGX_OK;
    case NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_JAEGER:
        exporter = opentelemetry_exporter_jaeger_create(&omcf->exporter_options.jaeger);
        break;
    case NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_OTLP_HTTP:
        exporter = opentelemetry_exporter_otlp_http_create(&omcf->exporter_options.otlp_http);
        break;
    default:
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "unknown opentelemetry exporter type %ud", omcf->exporter_type);
        return NGX_OK;
    }
    if (exporter == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "opentelemetry exporter type %ud creation failed", omcf->exporter_type);
        return NGX_OK;
    }

    opentelemetry_processor *processor;

    switch (omcf->processor_type) {
    case NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_NONE:
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "no opentelemetry processor set");
        opentelemetry_exporter_destroy(exporter);
        return NGX_OK;
    case NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_SIMPLE:
        processor = opentelemetry_processor_simple(exporter);
        break;
    case NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH:
        processor = opentelemetry_processor_batch(exporter, &omcf->processor_options.batch_options);
        break;
    default:
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "unknown opentelemetry processor type %ud", omcf->processor_type);
        opentelemetry_exporter_destroy(exporter);
        return NGX_OK;
    }

    if (processor == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "opentelemetry processor type %ud creation failed", omcf->processor_type);
        opentelemetry_exporter_destroy(exporter);
        return NGX_OK;
    }

    opentelemetry_sampler *sampler = NULL;

    if (omcf->tracestate_debug_key.len != 0) {
        sampler = opentelemetry_sampler_parent_root(ngx_http_opentelemetry_sampler, cycle);
        if (sampler == NULL) {
            ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "opentelemetry sampler creation failed");
            opentelemetry_processor_destroy(processor);
            return NGX_OK;
        }
    }

    opentelemetry_attribute provider_attrs[] = {
        OPENTELEMETRY_ATTRIBUTE_STR("service.name", (char*)omcf->service_name.data, omcf->service_name.len),
        OPENTELEMETRY_ATTRIBUTE_STR("host.name", (char*)cycle->hostname.data, cycle->hostname.len),
    };

    provider = opentelemetry_provider_create(processor, sampler, provider_attrs, sizeof(provider_attrs) / sizeof(provider_attrs[0]));
    if (provider == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "opentelemetry provider creation failed");
        if (sampler != NULL)
            opentelemetry_sampler_destroy(sampler);
        opentelemetry_processor_destroy(processor);
        return NGX_OK;
    }

    tracer = opentelemetry_provider_get_tracer(provider, "nginx_opentelemetry_module", NULL, NULL);
    if (tracer == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "opentelemetry tracer creation failed");
        opentelemetry_provider_destroy(provider);
        provider = NULL;
        return NGX_OK;
    }

    if (omcf->limit_span_size)
        opentelemetry_tracer_limit_span_size(tracer, true);

    return NGX_OK;
}

static void
ngx_http_opentelemetry_exit_process(ngx_cycle_t *cycle)
{
    if (tracer != NULL) {
        opentelemetry_tracer_destroy(tracer);
        tracer = NULL;
    }

    if (provider != NULL) {
        opentelemetry_provider_destroy(provider);
        provider = NULL;
    }
}

static void *
ngx_http_opentelemetry_create_main_conf(ngx_conf_t *cf)
{
    ngx_http_opentelemetry_main_conf_t *omcf;

    if ((omcf = ngx_pcalloc(cf->pool, sizeof(*omcf))) == NULL)
        return NGX_CONF_ERROR;

    omcf->limit_span_size = NGX_CONF_UNSET;

    return omcf;
}

static char *
ngx_http_opentelemetry_init_main_conf(ngx_conf_t* cf, void *conf)
{
    ngx_http_opentelemetry_main_conf_t *omcf = conf;

    ngx_conf_merge_value(omcf->limit_span_size, NGX_CONF_UNSET, 0);

    return NGX_CONF_OK;
}

static void *
ngx_http_opentelemetry_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_opentelemetry_loc_conf_t *olcf;

    if ((olcf = ngx_pcalloc(cf->pool, sizeof(*olcf))) == NULL)
        return NULL;

    olcf->sample = -1;
    olcf->parent = NGX_CONF_UNSET;

    return olcf;
}


static char *
ngx_http_opentelemetry_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_opentelemetry_loc_conf_t *prev = parent;
    ngx_http_opentelemetry_loc_conf_t *olcf = child;

    if (olcf->from == NULL)
        olcf->from = prev->from;

    ngx_conf_merge_value(olcf->parent, prev->parent, 0);

    if (olcf->parent_from == NULL)
        olcf->parent_from = prev->parent_from;

    if (olcf->variable == NULL)
        olcf->variable = prev->variable;

    if (olcf->sample < 0)
        olcf->sample = (prev->sample < 0) ? 0 : prev->sample;

    return NGX_CONF_OK;
}

static void
ngx_http_opentelemetry_cleanup(void *data)
{
    ngx_http_opentelemetry_ctx_t *ctx = data;

    if (ctx->request_span != NULL)
        opentelemetry_span_finish(ctx->request_span);
}

static ngx_http_opentelemetry_ctx_t *
ngx_http_opentelemetry_get_module_ctx(ngx_http_request_t *r)
{
    ngx_http_opentelemetry_ctx_t  *ctx;

    ctx = ngx_http_get_module_ctx(r->main, ngx_http_opentelemetry_module);

    return ctx;
}

static ngx_http_opentelemetry_ctx_t *
ngx_http_opentelemetry_add_module_ctx(ngx_http_request_t *r)
{
    ngx_http_opentelemetry_ctx_t       *ctx;
    ngx_pool_cleanup_t                 *cln;

    cln = ngx_pool_cleanup_add(r->pool, sizeof(*ctx));
    if (cln == NULL)
        return NULL;

    ctx = cln->data;
    ngx_memzero(ctx, sizeof(*ctx));

    cln->handler = ngx_http_opentelemetry_cleanup;

    ngx_http_set_ctx(r, ctx, ngx_http_opentelemetry_module);

    return ctx;
}

static void
ngx_http_opentelemetry_log_x_request_id(ngx_http_request_t *r, opentelemetry_span *span)
{
    static const ngx_str_t x_request_id_name = ngx_string("x_request_id");
    static ngx_uint_t x_request_id_hash;
    const ngx_http_variable_value_t *x_request_id_var;

    if (!x_request_id_hash)
        x_request_id_hash = ngx_hash_key(x_request_id_name.data, x_request_id_name.len);
    x_request_id_var = ngx_http_get_variable(r, (ngx_str_t*)&x_request_id_name, x_request_id_hash);
    if (x_request_id_var != NULL && !x_request_id_var->not_found && x_request_id_var->valid && x_request_id_var->len != 0) {
        opentelemetry_attribute x_request_id = OPENTELEMETRY_ATTRIBUTE_STR("x_request_id", (char*)x_request_id_var->data, x_request_id_var->len);

        opentelemetry_span_set_attribute(span, &x_request_id);
    }
}

typedef struct ngx_http_opentelemetry_headers_list {
    ngx_str_t header_name;
    ngx_array_t header_values;
} ngx_http_opentelemetry_headers_list;

static ngx_int_t
ngx_http_opentelemetry_set_request_headers_attributes(ngx_http_request_t *r, opentelemetry_span *span)
{
    ngx_http_opentelemetry_headers_list *headers_list;
    ngx_array_t                          headers;
    ngx_table_elt_t                     *header;
    ngx_list_part_t                     *part;
    ngx_uint_t                           i, j;

    if (ngx_array_init(&headers, r->pool, 1, sizeof(ngx_http_opentelemetry_headers_list)) != NGX_OK)
        return NGX_ERROR;

    part = &r->headers_in.headers.part;
    header = part->elts;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL)
                break;

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0)
            continue;

        for (j = 0; j < headers.nelts; j++) {
            headers_list = &((ngx_http_opentelemetry_headers_list*)headers.elts)[j];
            if (headers_list->header_name.len != header[i].key.len)
                continue;

            if (ngx_strncmp(headers_list->header_name.data, header[i].lowcase_key, header[i].key.len) == 0)
                break;
        }

        if (j == headers.nelts) {
            headers_list = ngx_array_push(&headers);
            if (headers_list == NULL)
                return NGX_ERROR;

            headers_list->header_name.data = header[i].lowcase_key;
            headers_list->header_name.len = header[i].key.len;
            if (ngx_array_init(&headers_list->header_values, r->pool, 1, sizeof(opentelemetry_string)) != NGX_OK)
                return NGX_ERROR;
        }

        opentelemetry_string *header_value = ngx_array_push(&headers_list->header_values);
        if (header_value == NULL)
            return NGX_ERROR;

        header_value->len = header[i].value.len;
        header_value->ptr = (const char*)header[i].value.data;
    }

    for (i = 0; i < headers.nelts; i++) {
        headers_list = &((ngx_http_opentelemetry_headers_list*)headers.elts)[i];

        size_t header_name_len = ngx_http_opentelemetry_request_header_attribute_prefix.len + headers_list->header_name.len;
        u_char *header_name = (u_char*)ngx_palloc(r->pool, header_name_len);
        if (header_name == NULL)
            return NGX_ERROR;
        u_char *header_name_begin = header_name;

        header_name = ngx_copy(header_name, ngx_http_opentelemetry_request_header_attribute_prefix.ptr, ngx_http_opentelemetry_request_header_attribute_prefix.len);
        ngx_memcpy(header_name, headers_list->header_name.data, headers_list->header_name.len);

        opentelemetry_attribute attribute = OPENTELEMETRY_ATTRIBUTE(
            OPENTELEMETRY_STR((char*)header_name_begin, header_name_len),
            OPENTELEMETRY_VALUE_ARRAY_STR(headers_list->header_values.elts, headers_list->header_values.nelts)
        );
        opentelemetry_span_set_attribute(span, &attribute);
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_opentelemetry_request_log(ngx_http_request_t *r, opentelemetry_span *span, bool log_x_request_id)
{
    opentelemetry_attribute uri = OPENTELEMETRY_ATTRIBUTE_STR("uri", (char*)r->uri.data, r->uri.len);

    opentelemetry_span_set_attribute(span, &uri);
    if (r->args.len != 0) {
        opentelemetry_attribute args = OPENTELEMETRY_ATTRIBUTE_STR("args", (char*)r->args.data, r->args.len);
        opentelemetry_span_set_attribute(span, &args);
    }

    if (ngx_http_opentelemetry_set_request_headers_attributes(r, span) != NGX_OK)
        return NGX_ERROR;

    if (log_x_request_id)
        ngx_http_opentelemetry_log_x_request_id(r, span);

    return NGX_OK;
}

static const char *ngx_http_opentelemetry_parent_header_value(const char *name, size_t name_len, size_t *value_len, void *arg)
{
    ngx_http_request_t *r = arg;

    ngx_list_part_t *part = &r->headers_in.headers.part;
    ngx_table_elt_t *header = part->elts;
    ngx_uint_t i;

    /* here we assume that the name passed is in lower case */

    for (i = 0; /* void */ ; i++) {

        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0 || header[i].key.len != name_len || ngx_memcmp(header[i].lowcase_key, name, name_len))
            continue;

        *value_len = header[i].value.len;
        return (char*)header[i].value.data;
    }

    return NULL;
}

static ngx_int_t
ngx_http_opentelemetry_parent(ngx_http_request_t *r, ngx_http_opentelemetry_loc_conf_t *olcf)
{
    if (olcf->parent_from != NULL && ngx_cidr_match(r->connection->sockaddr, olcf->parent_from) != NGX_OK)
        return NGX_DECLINED;

    opentelemetry_span *span = ngx_http_opentelemetry_span_start_headers(
        r, ngx_http_opentelemetry_request_name.ptr, ngx_http_opentelemetry_request_name.len,
        ngx_http_opentelemetry_parent_header_value, r);

    if (span == NULL)
        return NGX_DECLINED;

    opentelemetry_span_set_attribute(span, &(opentelemetry_attribute)OPENTELEMETRY_ATTRIBUTE_BOOL("parent", true));

    return NGX_OK;
}

static ngx_int_t
ngx_http_opentelemetry_handler(ngx_http_request_t *r, ngx_uint_t phase)
{
    ngx_http_opentelemetry_ctx_t       *ctx;
    ngx_http_opentelemetry_loc_conf_t  *olcf;

    if (!tracer)
        return NGX_DECLINED;

    bool log_x_request_id = (phase == NGX_HTTP_PREACCESS_PHASE);

    ctx = ngx_http_opentelemetry_get_module_ctx(r);

    if (ctx) {
        if (ctx->request_span && log_x_request_id)
            ngx_http_opentelemetry_log_x_request_id(r, ctx->request_span);
        return NGX_DECLINED;
    }

    olcf = ngx_http_get_module_loc_conf(r, ngx_http_opentelemetry_module);

    if (olcf->parent) {
        ngx_int_t rc = ngx_http_opentelemetry_parent(r, olcf);

        if (rc != NGX_DECLINED) {
            ctx = ngx_http_opentelemetry_get_module_ctx(r);
            if (ngx_http_opentelemetry_request_log(r, ctx->request_span, log_x_request_id) != NGX_OK)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            return rc == NGX_OK ? NGX_DECLINED : rc;
        }
    }

    if (olcf->variable == NULL)
        return NGX_DECLINED;

    unsigned tracing_level = 0;
    int sample = 0;
    sampler_debug = false;

    if (olcf->from == NULL || ngx_cidr_match(r->connection->sockaddr, olcf->from) == NGX_OK) {

        ngx_str_t value = ngx_null_string;
        ngx_http_complex_value_t *cv = olcf->variable;
        if (ngx_http_complex_value(r, cv, &value) != NGX_OK)
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        if (value.len > 1)
            tracing_level = 1;
        else if (value.len == 1 && *value.data != '0') {
            tracing_level = 1;
            if (*value.data >= '2' && *value.data <= '9') {
                tracing_level = 2;
                sampler_debug = true;
            }
        }
    }
    if (tracing_level == 0 && olcf->sample > 0) {
        sample = (ngx_random() / (double)((uint64_t)RAND_MAX + 1)) < olcf->sample;
        if (sample)
            tracing_level = 1;
    }

    ctx = ngx_http_opentelemetry_add_module_ctx(r);
    if (ctx == NULL)
        return NGX_HTTP_INTERNAL_SERVER_ERROR;

    if (tracing_level > 0) {
        ctx->request_span = opentelemetry_span_start(tracer, &ngx_http_opentelemetry_request_name, NULL);
        if (ctx->request_span != NULL) {
            ctx->tracing_level = tracing_level;
            if (ngx_http_opentelemetry_request_log(r, ctx->request_span, log_x_request_id) != NGX_OK)
                return NGX_HTTP_INTERNAL_SERVER_ERROR;

            if (sample)
                opentelemetry_span_set_attribute(ctx->request_span, &(opentelemetry_attribute)OPENTELEMETRY_ATTRIBUTE_BOOL("sample", true));
            else
                opentelemetry_span_set_attribute(ctx->request_span, &(opentelemetry_attribute)OPENTELEMETRY_ATTRIBUTE_BOOL("user", true));
        }
    }

    return NGX_DECLINED;
}

static ngx_int_t
ngx_http_opentelemetry_server_rewrite_handler(ngx_http_request_t *r)
{
    return ngx_http_opentelemetry_handler(r, NGX_HTTP_SERVER_REWRITE_PHASE);
}

static ngx_int_t
ngx_http_opentelemetry_preaccess_handler(ngx_http_request_t *r)
{
    return ngx_http_opentelemetry_handler(r, NGX_HTTP_PREACCESS_PHASE);
}

static ngx_int_t
ngx_http_opentelemetry_preconf(ngx_conf_t *cf)
{
    ngx_http_variable_t *var, *v;

    for (v = ngx_http_opentelemetry_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL)
            return NGX_ERROR;

        var->get_handler = v->get_handler;
        var->data = v->data;
    }

    return NGX_OK;
}

static ngx_int_t
ngx_http_opentelemetry_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *omcf;

    omcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&omcf->phases[NGX_HTTP_SERVER_REWRITE_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_opentelemetry_server_rewrite_handler;

    h = ngx_array_push(&omcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL)
        return NGX_ERROR;

    *h = ngx_http_opentelemetry_preaccess_handler;

    return NGX_OK;
}

static char*
ngx_http_set_opentelemetry_jaeger_exporter_options(ngx_conf_t *cf, opentelemetry_exporter_jaeger_options *jaeger_options) {
    jaeger_options->format = NGX_HTTP_OPENTELEMETRY_EXPORTER_JAEGER_OPTION_FORMAT_DEFAULT;
    jaeger_options->server_port = NGX_HTTP_OPENTELEMETRY_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT_SERVER_PORT_DEFAULT;
    bool server_port_auto_specified = true;

    char *token, *saveptr;
    for (token = strtok_r((char*)((ngx_str_t*)cf->args->elts)[2].data, "|", &saveptr); token; token = strtok_r(NULL, "|", &saveptr)) {
        char *equals = ngx_strchr(token, '=');
        if (!equals) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid exporter options");
            return NGX_CONF_ERROR;
        }
        *equals = '\0';

        char *value_begin = equals + 1;
        size_t value_len = strlen(value_begin);
        if (equals - token < 1 || value_len < 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid exporter options");
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(token, "format") == 0) {
            if (ngx_strcmp(value_begin, "thrift_udp_compact") == 0) {
                jaeger_options->format = OPENTELEMETRY_C_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT;
                if (server_port_auto_specified)
                    jaeger_options->server_port = NGX_HTTP_OPENTELEMETRY_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT_SERVER_PORT_DEFAULT;
            } else if (ngx_strcmp(value_begin, "thrift_http") == 0) {
                jaeger_options->format = OPENTELEMETRY_C_EXPORTER_JAEGER_FORMAT_THRIFT_HTTP;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid format exporter option");
                return NGX_CONF_ERROR;
            }
        } else if (ngx_strcmp(token, "endpoint") == 0) {
            jaeger_options->endpoint = value_begin;
        } else if (ngx_strcmp(token, "server_port") == 0) {
            ngx_int_t server_port = ngx_atoi((u_char*)value_begin, value_len);
            if (server_port == NGX_ERROR || server_port > UINT16_MAX) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid server_port exporter option");
                return NGX_CONF_ERROR;
            }
            jaeger_options->server_port = server_port;
            server_port_auto_specified = false;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid exporter option: \"%s\"", token);
            return NGX_CONF_ERROR;
        }
    }

    if (!jaeger_options->endpoint) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "exporter endpoint is missed");
        return NGX_CONF_ERROR;
    } else if (jaeger_options->format == OPENTELEMETRY_C_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT && !jaeger_options->server_port) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "exporter server_port is missed");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_set_opentelemetry_otlp_http_exporter_options(ngx_conf_t *cf, opentelemetry_exporter_otlp_http_options *otlp_http_options)
{
    otlp_http_options->content_type = NGX_HTTP_OPENTELEMETRY_EXPORTER_OTLP_HTTP_OPTION_CONTENT_TYPE_DEFAULT;
    otlp_http_options->json_bytes_mapping = NGX_HTTP_OPENTELEMETRY_EXPORTER_OTLP_HTTP_OPTION_JSON_BYTES_MAPPING_DEFAULT;

    size_t headers_len = 0, headers_cap = 0;
    opentelemetry_http_header *headers = NULL;

    char *token, *saveptr;
    for (token = strtok_r((char*)((ngx_str_t*)cf->args->elts)[2].data, "|", &saveptr); token; token = strtok_r(NULL, "|", &saveptr)) {
        char *equals = ngx_strchr(token, '=');
        if (!equals) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid exporter options");
            return NGX_CONF_ERROR;
        }
        *equals = '\0';

        char *value_begin = equals + 1;
        size_t value_len = strlen(value_begin);
        if (equals - token < 1 || value_len < 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid exporter options");
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(token, "url") == 0) {
            otlp_http_options->url = value_begin;
        } else if (ngx_strcmp(token, "content_type") == 0) {
            if (ngx_strcmp(value_begin, "json") == 0) {
                otlp_http_options->content_type = OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_CONTENT_TYPE_JSON;
            } else if (ngx_strcmp(value_begin, "binary") == 0) {
                otlp_http_options->content_type = OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_CONTENT_TYPE_BINARY;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid content_type exporter option");
                return NGX_CONF_ERROR;
            }
        } else if (ngx_strcmp(token, "json_bytes_mapping") == 0) {
            if (ngx_strcmp(value_begin, "khexid") == 0) {
                otlp_http_options->json_bytes_mapping = OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_JSON_BMAPPING_KHEXID;
            } else if (ngx_strcmp(value_begin, "khex") == 0) {
                otlp_http_options->json_bytes_mapping = OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_JSON_BMAPPING_KHEX;
            } else if (ngx_strcmp(value_begin, "kbase64") == 0) {
                otlp_http_options->json_bytes_mapping = OPENTELEMETRY_C_EXPORTER_OTLP_HTTP_JSON_BMAPPING_KBASE64;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid json_bytes_mapping exporter option");
                return NGX_CONF_ERROR;
            }
        } else if (ngx_strcmp(token, "header") == 0) {
            char *colon = strchr(value_begin, ':');
            if (!colon) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid header exporter options");
                return NGX_CONF_ERROR;
            }
            *colon = '\0';

            size_t header_name_len = colon - value_begin;
            char *header_value_begin = colon + 1;
            while (*header_value_begin == ' ')
                header_value_begin++;
            size_t header_value_len = value_len - (header_value_begin - value_begin);

            if (header_name_len < 1 || header_value_len < 1) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid header exporter options");
                return NGX_CONF_ERROR;
            }

            if (headers_len == 0) {
                headers = (opentelemetry_http_header*)ngx_palloc(cf->pool, 2 * sizeof(opentelemetry_http_header));
                if (headers == NULL)
                    return NGX_CONF_ERROR;

                headers_cap = 2;
            } else if (headers_len == headers_cap) {
                opentelemetry_http_header *old_headers = headers;
                headers_cap *= 2;
                headers = (opentelemetry_http_header*)ngx_palloc(cf->pool, headers_cap * sizeof(opentelemetry_http_header));
                if (headers == NULL)
                    return NGX_CONF_ERROR;

                size_t itr;
                for (itr = 0; itr < headers_len; itr++) {
                    headers[itr] = old_headers[itr];
                }
            }

            headers[headers_len].name.len = header_name_len;
            headers[headers_len].name.ptr = token;
            headers[headers_len].value.len = header_value_len;
            headers[headers_len].value.ptr = header_value_begin;

            headers_len++;

        } else if (ngx_strcmp(token, "max_concurrent_requests") == 0) {
            ngx_int_t max_concurrent_requests = ngx_atoi((u_char*)value_begin, value_len);
            if (max_concurrent_requests == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_concurrent_requests exporter option");
                return NGX_CONF_ERROR;
            }
            otlp_http_options->max_concurrent_requests = (size_t)max_concurrent_requests;
        } else if (ngx_strcmp(token, "max_requests_per_connection") == 0) {
            ngx_int_t max_requests_per_connection = ngx_atoi((u_char*)value_begin, value_len);
            if (max_requests_per_connection == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_requests_per_connection exporter option");
                return NGX_CONF_ERROR;
            }
            otlp_http_options->max_requests_per_connection = (size_t)max_requests_per_connection;
        } else if (ngx_strcmp(token, "timeout") == 0) {
            ngx_int_t timeout = ngx_atoi((u_char*)value_begin, value_len);
            if (timeout == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid timeout exporter option");
                return NGX_CONF_ERROR;
            }
            otlp_http_options->timeout.tv_sec = timeout / 1000;
            otlp_http_options->timeout.tv_nsec = (timeout % 1000) * 1000000;
            otlp_http_options->timeout_set = true;
        } else if (ngx_strcmp(token, "use_json_name") == 0) {
            if (ngx_strcmp(value_begin, "true") == 0) {
                otlp_http_options->use_json_name = true;
            } else if (ngx_strcmp(value_begin, "false") == 0) {
                otlp_http_options->use_json_name = false;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid use_json_name exporter option");
                return NGX_CONF_ERROR;
            }
        } else if (ngx_strcmp(token, "console_debug") == 0) {
            if (ngx_strcmp(value_begin, "true") == 0) {
                otlp_http_options->console_debug = true;
            } else if (ngx_strcmp(value_begin, "false") == 0) {
                otlp_http_options->console_debug = false;
            } else {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid console_debug exporter option");
                return NGX_CONF_ERROR;
            }
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid exporter option: \"%s\"", token);
            return NGX_CONF_ERROR;
        }
    }

    if (!otlp_http_options->url) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "exporter url is missed");
        return NGX_CONF_ERROR;
    }

    if (headers_len) {
       otlp_http_options->nheaders = headers_len;
       otlp_http_options->headers = headers;
       otlp_http_options->headers_set = true;
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_set_opentelemetry_batch_processor_options(ngx_conf_t *cf, opentelemetry_processor_batch_options *batch_options)
{
    batch_options->max_queue_size = NGX_HTTP_OPENTELEMETRY_PROCESSOR_BATCH_OPTION_MAX_QUEUE_SIZE_DEFAULT;
    batch_options->schedule_delay_millis = NGX_HTTP_OPENTELEMETRY_PROCESSOR_BATCH_OPTION_SCHEDULE_DELAY_MILLIS_DEFAULT;
    batch_options->max_export_batch_size = NGX_HTTP_OPENTELEMETRY_PROCESSOR_BATCH_OPTION_MAX_EXPORT_BATCH_SIZE_DEFAULT;

    if (cf->args->nelts <= 4)
        return NGX_CONF_OK;

    char *token, *saveptr;
    for (token = strtok_r((char*)((ngx_str_t*)cf->args->elts)[4].data, "|", &saveptr); token; token = strtok_r(NULL, "|", &saveptr)) {
        char *equals = ngx_strchr(token, '=');
        if (!equals) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid processor options");
            return NGX_CONF_ERROR;
        }
        *equals = '\0';

        char *value_begin = equals + 1;
        size_t value_len = strlen(value_begin);
        if (equals - token < 1 || value_len < 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid processor options");
            return NGX_CONF_ERROR;
        }

        if (ngx_strcmp(token, "max_queue_size") == 0) {
            ngx_int_t max_queue_size = ngx_atoi((u_char*)value_begin, value_len);
            if (max_queue_size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_queue_size processor option");
                return NGX_CONF_ERROR;
            }
            batch_options->max_queue_size = (size_t)max_queue_size;
        } else if (ngx_strcmp(token, "schedule_delay_millis") == 0) {
            ngx_int_t schedule_delay_millis = ngx_atoi((u_char*)value_begin, value_len);
            if (schedule_delay_millis == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid schedule_delay_millis processor option");
                return NGX_CONF_ERROR;
            }
            batch_options->schedule_delay_millis = (int64_t)schedule_delay_millis;
        } else if (ngx_strcmp(token, "max_export_batch_size") == 0) {
            ngx_int_t max_export_batch_size = ngx_atoi((u_char*)value_begin, value_len);
            if (max_export_batch_size == NGX_ERROR) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "invalid max_export_batch_size processor option");
                return NGX_CONF_ERROR;
            }
            batch_options->max_export_batch_size = (size_t)max_export_batch_size;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid processor option: \"%s\"", token);
            return NGX_CONF_ERROR;
        }
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_check_opentelemetry_exporter(ngx_conf_t *cf, ngx_http_opentelemetry_main_conf_t *omcf)
{
    opentelemetry_exporter *exporter;
    if (omcf->exporter_type == NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_JAEGER)
        exporter = opentelemetry_exporter_jaeger_create(&omcf->exporter_options.jaeger);
    else if (omcf->exporter_type == NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_OTLP_HTTP)
        exporter = opentelemetry_exporter_otlp_http_create(&omcf->exporter_options.otlp_http);

    if (exporter == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "opentelemetry exporter type %ud creation failed", omcf->exporter_type);
        return NGX_CONF_ERROR;
    }

    opentelemetry_processor *processor;
    if (omcf->processor_type == NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_SIMPLE)
        processor = opentelemetry_processor_simple(exporter);
    else if (omcf->processor_type == NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH)
        processor = opentelemetry_processor_batch(exporter, &omcf->processor_options.batch_options);

    if (processor == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "opentelemetry processor type %ud creation failed", omcf->processor_type);
        opentelemetry_exporter_destroy(exporter);
        return NGX_CONF_ERROR;
    }

    opentelemetry_processor_destroy(processor);
    return NGX_CONF_OK;
}

static char*
ngx_http_set_opentelemetry_exporter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_opentelemetry_main_conf_t *omcf = conf;
    ngx_str_t *values = cf->args->elts;

    if (omcf->exporter_type != NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_NONE)
        return "is duplicate";

    char *res;
    if (ngx_strcmp(values[1].data, "jaeger") == 0) {
        omcf->exporter_type = NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_JAEGER;
        res = ngx_http_set_opentelemetry_jaeger_exporter_options(cf, &omcf->exporter_options.jaeger);
    } else if (ngx_strcmp(values[1].data, "otlp_http") == 0) {
        omcf->exporter_type = NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_OTLP_HTTP;
        res = ngx_http_set_opentelemetry_otlp_http_exporter_options(cf, &omcf->exporter_options.otlp_http);
    } else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unknown exporter type: \"%V\"", &values[1]);
        return NGX_CONF_ERROR;
    }

    if (res != NGX_CONF_OK)
        return res;

    if (cf->args->nelts > 3) {
        if (ngx_strcmp(values[3].data, "batch") == 0) {
            omcf->processor_type = NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH;
        } else if (ngx_strcmp(values[3].data, "simple") == 0) {
            omcf->processor_type = NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_SIMPLE;
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "unknown processor type: \"%V\"", &values[1]);
            return NGX_CONF_ERROR;
        }
    } else {
        omcf->processor_type = NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_DEFAULT;
    }

    if (omcf->processor_type == NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH) {
        res = ngx_http_set_opentelemetry_batch_processor_options(cf, &omcf->processor_options.batch_options);
        if (res != NGX_CONF_OK)
            return res;
    } else if (cf->args->nelts > 4) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "only batch processor has processor options");
        return NGX_CONF_ERROR;
    }

    return ngx_http_check_opentelemetry_exporter(cf, omcf);
}

static char*
ngx_http_set_opentelemetry_tracestate_debug(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_opentelemetry_main_conf_t *omcf = conf;
    ngx_str_t *values = cf->args->elts;

    if (omcf->tracestate_debug_key.len != 0)
        return "is duplicate";

    if (values[1].len == 0)
        return "is invalid (zero key length)";

    omcf->tracestate_debug_key = values[1];
    omcf->tracestate_debug_value = values[2];

    return NGX_CONF_OK;
}

static char*
ngx_http_set_opentelemetry_from(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_array_t **parray = conf + cmd->offset;

    ngx_int_t                rc;
    ngx_str_t               *value;
    ngx_cidr_t              *cidr;

    value = cf->args->elts;

    if (*parray == NULL) {
        *parray = ngx_array_create(cf->pool, 2,
                                      sizeof(ngx_cidr_t));
        if (*parray == NULL)
            return NGX_CONF_ERROR;
    }

    cidr = ngx_array_push(*parray);
    if (cidr == NULL)
        return NGX_CONF_ERROR;

#if (NGX_HAVE_UNIX_DOMAIN)

    if (ngx_strcmp(value[1].data, "unix:") == 0) {
        cidr->family = AF_UNIX;
        return NGX_CONF_OK;
    }

#endif

    rc = ngx_ptocidr(&value[1], cidr);

    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid parameter \"%V\"",
                           &value[1]);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "low address bits of %V are meaningless", &value[1]);
    }

    return NGX_CONF_OK;
}

static char*
ngx_http_set_opentelemetry_variable(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_opentelemetry_loc_conf_t *olcf = conf;
    ngx_http_compile_complex_value_t  ccv;

    if (olcf->variable)
        return "is duplicate";

    olcf->variable = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));

    ngx_memzero(&ccv, sizeof(ccv));
    ccv.cf = cf;
    ccv.value = &((ngx_str_t*)cf->args->elts)[1];
    ccv.complex_value = olcf->variable;
    if (ccv.complex_value == NULL)
        return NGX_CONF_ERROR;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK)
        return NGX_CONF_ERROR;

    return NGX_CONF_OK;
}

static char*
ngx_http_set_opentelemetry_sample(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_opentelemetry_loc_conf_t *olcf = conf;
    ngx_str_t *value = cf->args->elts;

    if (olcf->sample >= 0)
        return "is duplicate";

    ngx_int_t sample_i = ngx_atofp(value[1].data, value[1].len, 9);
    if (sample_i < 0 || sample_i > 1000000000)
        return "is invalid";

    olcf->sample = sample_i / (double)1000000000;

    return NGX_CONF_OK;
}

ngx_int_t
ngx_http_opentelemetry_is_enabled(ngx_http_request_t *r)
{
    ngx_http_opentelemetry_ctx_t       *ctx;

    ctx = ngx_http_opentelemetry_get_module_ctx(r);

    if (!ctx || !ctx->tracing_level)
        return 0;

    if (!tracer)
         return 0;

    return 1;
}

opentelemetry_span *
ngx_http_opentelemetry_get_request_span(ngx_http_request_t *r)
{
    ngx_http_opentelemetry_ctx_t       *ctx;

    if (!ngx_http_opentelemetry_is_enabled(r))
        return NULL;

    ctx = ngx_http_opentelemetry_get_module_ctx(r);
    return ctx->request_span;
}

opentelemetry_span *
ngx_http_opentelemetry_span_start(ngx_http_request_t *r, opentelemetry_span *parent, const char *operation_name, size_t operation_name_len)
{
    opentelemetry_string name = OPENTELEMETRY_STR(operation_name, operation_name_len);
    opentelemetry_span *span = opentelemetry_span_start(tracer, &name, parent);
    return span;
}

int ngx_http_opentelemetry_span_debug(ngx_http_request_t *r, opentelemetry_span *span)
{
    if (!ngx_http_opentelemetry_is_enabled(r))
        return 0;

    ngx_http_opentelemetry_ctx_t *ctx = ngx_http_opentelemetry_get_module_ctx(r);

    return ctx->tracing_level > 1;
}

int
ngx_http_opentelemetry_span_headers_get(ngx_http_request_t *r, opentelemetry_span *span, opentelemetry_header_each header_each, void *header_each_arg)
{
    if (!ngx_http_opentelemetry_is_enabled(r))
        return -1;

    return opentelemetry_span_headers_get(span, header_each, header_each_arg);
}

opentelemetry_span *
ngx_http_opentelemetry_span_start_headers(ngx_http_request_t *r, const char *operation_name, size_t operation_name_len, opentelemetry_header_value header_value, void *header_value_arg)
{
    opentelemetry_string name = OPENTELEMETRY_STR(operation_name, operation_name_len);
    opentelemetry_span *span = opentelemetry_span_start_headers(tracer, &name, header_value, header_value_arg);
    if (span == NULL)
        return NULL;

    ngx_http_opentelemetry_ctx_t *ctx = ngx_http_opentelemetry_get_module_ctx(r);
    if (ctx == NULL) {
        if ((ctx = ngx_http_opentelemetry_add_module_ctx(r)) == NULL) {
            opentelemetry_span_finish(span);
            return NULL;
        }
    }
    if (ctx->request_span == NULL) {
        ngx_http_opentelemetry_main_conf_t *omcf = ngx_http_get_module_main_conf(r, ngx_http_opentelemetry_module);

        ctx->request_span = span;
        ctx->tracing_level = 1;
        if (omcf->tracestate_debug_key.len != 0) {
            opentelemetry_trace_state *ts = opentelemetry_span_trace_state_get(span);
            char value[omcf->tracestate_debug_value.len + 2];
            size_t value_len = sizeof(value) - 1;

            if (ts != NULL && opentelemetry_trace_state_get(
                    ts, (char*)omcf->tracestate_debug_key.data, omcf->tracestate_debug_key.len,
                    value, &value_len)) {
                if (value_len == omcf->tracestate_debug_value.len && !memcmp(value, omcf->tracestate_debug_value.data, value_len))
                    ctx->tracing_level = 2;
            }
        }
    }

    return span;
}

void
ngx_http_opentelemetry_span_finish(ngx_http_request_t *r, opentelemetry_span *span)
{
    if (!ngx_http_opentelemetry_is_enabled(r))
        return;

    ngx_http_opentelemetry_ctx_t *ctx = ngx_http_opentelemetry_get_module_ctx(r);
    opentelemetry_span *request_span = ctx->request_span;

    opentelemetry_span_finish(span);

    if (span == request_span) {
        ctx->request_span = NULL;
        ctx->tracing_level = 0;
    }
}

typedef struct ngx_http_opentelemetry_header_variable_get_ctx {
    ngx_str_t *header_name;
    ngx_http_request_t *r;
    ngx_http_variable_value_t *v;
} ngx_http_opentelemetry_header_variable_get_ctx;

static int
ngx_http_opentelemetry_header_variable_get(const char *name, size_t name_len, const char *value, size_t value_len, void *arg)
{
    ngx_http_opentelemetry_header_variable_get_ctx *ctx = arg;
    ngx_str_t                                      *header_name = ctx->header_name;
    ngx_http_variable_value_t                      *v = ctx->v;
    u_char                                         *header_value;
    if (header_name->len != name_len || !ctx->v->not_found)
        return 0;

    if (ngx_strncmp(name, header_name->data, header_name->len) == 0) {
        header_value = (u_char*)ngx_palloc(ctx->r->pool, value_len);
        ngx_memcpy(header_value, value, value_len);
        v->data = header_value;
        v->len = value_len;
        v->valid = 1;
        v->no_cacheable = 0;
        v->not_found = 0;
    }

    return 0;
}

static ngx_int_t
ngx_http_opentelemetry_header_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data)
{
    ngx_http_opentelemetry_header_variable_get_ctx get_ctx;
    ngx_http_opentelemetry_ctx_t                  *ctx;
    ngx_str_t                                     *name;
    ngx_str_t                                      header_name;

    v->not_found = 1;

    if (!ngx_http_opentelemetry_is_enabled(r))
        return NGX_OK;

    ctx = ngx_http_opentelemetry_get_module_ctx(r);
    if (!ctx)
        return NGX_OK;

    if (!ctx->request_span)
        return NGX_OK;

    name = (ngx_str_t*)data;
    header_name.len = name->len - (sizeof(OPENTELEMETRY_HEADER_VARIABLE_PREFIX) - 1);
    header_name.data = name->data + sizeof(OPENTELEMETRY_HEADER_VARIABLE_PREFIX) - 1;

    get_ctx.header_name = &header_name;
    get_ctx.r = r;
    get_ctx.v = v;

    if (opentelemetry_span_headers_get(ctx->request_span, ngx_http_opentelemetry_header_variable_get, &get_ctx) < 0)
        return NGX_ERROR;

    return NGX_OK;
}
