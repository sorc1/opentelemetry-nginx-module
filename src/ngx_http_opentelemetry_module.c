#include "ngx_http_opentelemetry_module.h"
#include <opentelemetry-c/exporter_jaeger_trace.h>
#include <opentelemetry-c/exporter_otlp_http.h>

#define OPENTELEMETRY_HEADER_VARIABLE_PREFIX "opentelemetry_header_"

static const opentelemetry_string ngx_http_opentelemetry_request_name = OPENTELEMETRY_CSTR("request");

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
        struct {
            bool is_default;
            opentelemetry_processor_batch_options options;
        } batch;
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
static char *ngx_http_opentelemetry_init_main_conf(ngx_conf_t* cf, void *conf);
static void *ngx_http_opentelemetry_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_opentelemetry_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
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
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE12,
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

    { ngx_string("set_opentelemetry_from"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_from,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, from),
      NULL },

    { ngx_string("set_opentelemetry"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_variable,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_opentelemetry_sample"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_http_set_opentelemetry_sample,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("set_opentelemetry_parent"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_opentelemetry_loc_conf_t, parent),
      NULL },

    { ngx_string("set_opentelemetry_parent_from"),
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
        if (omcf->processor_options.batch.is_default)
            processor = opentelemetry_processor_batch(exporter, NULL);
        else
            processor = opentelemetry_processor_batch(exporter, &omcf->processor_options.batch.options);
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

    if ((omcf = ngx_pcalloc(cf->pool, sizeof(*omcf))) == NULL) {
        return NGX_CONF_ERROR;
    }
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

    if ((olcf = ngx_pcalloc(cf->pool, sizeof(*olcf))) == NULL) {
        return NULL;
    }
    olcf->sample = -1;
    olcf->parent = NGX_CONF_UNSET;

    return olcf;
}


static char *
ngx_http_opentelemetry_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_opentelemetry_loc_conf_t *prev = parent;
    ngx_http_opentelemetry_loc_conf_t *olcf = child;

    if (olcf->from == NULL) {
        olcf->from = prev->from;
    }

    ngx_conf_merge_value(olcf->parent, prev->parent, 0);

    if (olcf->parent_from == NULL) {
        olcf->parent_from = prev->parent_from;
    }

    if (olcf->variable == NULL) {
        olcf->variable = prev->variable;
    }

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
    x_request_id_var = ngx_http_get_variable(r, (ngx_str_t *)&x_request_id_name, x_request_id_hash);
    if (x_request_id_var != NULL && !x_request_id_var->not_found && x_request_id_var->valid && x_request_id_var->len != 0) {
        opentelemetry_attribute x_request_id = OPENTELEMETRY_ATTRIBUTE_STR("x_request_id", (char*)x_request_id_var->data, x_request_id_var->len);

        opentelemetry_span_set_attribute(span, &x_request_id);
    }
}

static void
ngx_http_opentelemetry_request_log(ngx_http_request_t *r, opentelemetry_span *span, bool log_x_request_id)
{
    opentelemetry_attribute uri = OPENTELEMETRY_ATTRIBUTE_STR("uri", (char*)r->uri.data, r->uri.len);

    opentelemetry_span_set_attribute(span, &uri);
    if (r->args.len != 0) {
        opentelemetry_attribute args = OPENTELEMETRY_ATTRIBUTE_STR("args", (char*)r->args.data, r->args.len);
        opentelemetry_span_set_attribute(span, &args);
    }
    if (log_x_request_id)
        ngx_http_opentelemetry_log_x_request_id(r, span);
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

    if (!tracer) {
        return NGX_DECLINED;
    }

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
            ngx_http_opentelemetry_request_log(r, ctx->request_span, log_x_request_id);
            return rc == NGX_OK ? NGX_DECLINED : rc;
        }
    }

    if (olcf->variable == NULL) {
        return NGX_DECLINED;
    }

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
    }

    ctx = ngx_http_opentelemetry_add_module_ctx(r);
    if (ctx == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (tracing_level > 0 || sample) {
        ctx->request_span = opentelemetry_span_start(tracer, &ngx_http_opentelemetry_request_name, NULL);
        if (ctx->request_span != NULL) {
            ctx->tracing_level = tracing_level;
            ngx_http_opentelemetry_request_log(r, ctx->request_span, log_x_request_id);

            if (tracing_level > 0)
                opentelemetry_span_set_attribute(ctx->request_span, &(opentelemetry_attribute)OPENTELEMETRY_ATTRIBUTE_BOOL("user", true));
            else
                opentelemetry_span_set_attribute(ctx->request_span, &(opentelemetry_attribute)OPENTELEMETRY_ATTRIBUTE_BOOL("sample", true));
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
        if (var == NULL) {
            return NGX_ERROR;
        }

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
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_opentelemetry_server_rewrite_handler;

    h = ngx_array_push(&omcf->phases[NGX_HTTP_PREACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_opentelemetry_preaccess_handler;

    return NGX_OK;
}

static char*
ngx_http_set_opentelemetry_exporter(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_http_opentelemetry_main_conf_t *omcf = conf;

    if (omcf->exporter_type != NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_NONE)
        return "is duplicate";

    /*
        TODO:
        - read exporter name & exporter options, set omcf->processor_kind appropriately
        - create and free exporter & processor (when custom processor options is set) as a test
        - return "is invalid" on errors
    */

    omcf->exporter_type = NGX_HTTP_OPENTELEMETRY_EXPORTER_TYPE_JAEGER;
    omcf->exporter_options.jaeger.format = OPENTELEMETRY_C_EXPORTER_JAEGER_FORMAT_THRIFT_UDP_COMPACT;
    omcf->exporter_options.jaeger.endpoint = "127.0.0.1";
    omcf->exporter_options.jaeger.server_port = 6831;

    omcf->processor_type = NGX_HTTP_OPENTELEMETRY_PROCESSOR_TYPE_BATCH;
    omcf->processor_options.batch.is_default = true;

    return NGX_CONF_OK;
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
        if (*parray == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    cidr = ngx_array_push(*parray);
    if (cidr == NULL) {
        return NGX_CONF_ERROR;
    }

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
    if (olcf->variable) {
        return "is duplicate";
    }

    olcf->variable = ngx_pcalloc(cf->pool, sizeof(ngx_http_complex_value_t));

    ngx_http_compile_complex_value_t  ccv;

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));

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

    if (!ngx_http_opentelemetry_is_enabled(r)) {
        return NULL;
    }

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
    if (!ngx_http_opentelemetry_is_enabled(r)) {
        return;
    }

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
        header_value = (u_char *)ngx_palloc(ctx->r->pool, value_len);
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

    name = (ngx_str_t *)data;
    header_name.len = name->len - (sizeof(OPENTELEMETRY_HEADER_VARIABLE_PREFIX) - 1);
    header_name.data = name->data + sizeof(OPENTELEMETRY_HEADER_VARIABLE_PREFIX) - 1;

    get_ctx.header_name = &header_name;
    get_ctx.r = r;
    get_ctx.v = v;

    if (opentelemetry_span_headers_get(ctx->request_span, ngx_http_opentelemetry_header_variable_get, &get_ctx) < 0)
        return NGX_ERROR;

    return NGX_OK;
}
