#ifndef DDEBUG
#define DDEBUG 0
#endif
#include "ddebug.h"


#include "ngx_http_lua_opentelemetry.h"
#include "ngx_http_lua_util.h"

#include <stdbool.h>
#include <inttypes.h>
#include <stdlib.h>
#include <cjaeger.h>

static char ngx_http_lua_spans_key;

static void
ngx_http_lua_opentelemetry_get_spans(lua_State *L, void *key) {

    lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(spans_key));
    lua_rawget(L, LUA_REGISTRYINDEX);

    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_newtable(L);
        lua_pushlightuserdata(L, ngx_http_lua_lightudata_mask(spans_key));
        lua_pushvalue(L, -2);
        lua_rawset(L, LUA_REGISTRYINDEX);
    }

    lua_pushlightuserdata(L, key);
    lua_rawget(L, -2);
    return;
}

static opentelemetry_span *
ngx_http_lua_opentelemetry_span_peek(lua_State *L) {
    opentelemetry_span *span = NULL;

    ngx_http_lua_opentelemetry_get_spans(L, L);

    lua_State *P = L;
    while (lua_isnil(L, -1) || luaL_getn(L, -1) == 0) {
        ngx_http_request_t *r = ngx_http_lua_get_req(L);
        ngx_http_lua_ctx_t *ctx = ngx_http_get_module_ctx(r, ngx_http_lua_module);
        ngx_http_lua_co_ctx_t *coctx = ngx_http_lua_get_co_ctx(P, ctx);
        if (coctx && coctx->parent_co_ctx) {
            lua_pop(L, 2);
            P = coctx->parent_co_ctx->co;
            ngx_http_lua_opentelemetry_get_spans(L, P);
        }
        else {
            break;
        }
    }

    if (!lua_isnil(L, -1) && luaL_getn(L, -1) != 0) {
        lua_rawgeti(L, -1, luaL_getn(L, -1));
        span = lua_touserdata(L, -1);
        lua_pop(L, 1);
    }
    lua_pop(L, 2);

    if (!span) {
        ngx_http_request_t *r = ngx_http_lua_get_req(L);
        span = ngx_http_opentelemetry_get_request_span(r);
    }

    return span;
}

static void
ngx_http_lua_opentelemetry_span_push(lua_State *L, opentelemetry_span *span) {

    ngx_http_lua_opentelemetry_get_spans(L, L);

    if (lua_isnil(L, -1)) {
        lua_pop(L, 1);
        lua_createtable(L, 1, 0);
        lua_pushlightuserdata(L, L);
        lua_pushvalue(L, -2);
        lua_rawset(L, -4);
    }

    lua_pushlightuserdata(L, span);
    lua_rawseti(L, -2, luaL_getn(L, -2) + 1);
    lua_pop(L, 2);
}

static void
ngx_http_lua_opentelemetry_span_pop(lua_State *L) {

    ngx_http_lua_opentelemetry_get_spans(L, L);

    if (lua_isnil(L, -1)) {
        lua_pop(L, 2);
        return;
    }

    size_t n = luaL_getn(L, -1);
    if (n > 0) {
        lua_pushnil(L);
        lua_rawseti(L, -2, luaL_getn(L, -2));
    }
    lua_pop(L, 2);
}

void
ngx_http_lua_opentelemetry_span_start_helper(void *data, const char *operation_name, size_t operation_name_len) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_opentelemetry_is_enabled(r))
        return;

    opentelemetry_span *parent = ngx_http_lua_opentelemetry_span_peek(L);
    opentelemetry_span *span = ngx_http_opentelemetry_span_start(r, parent, operation_name, operation_name_len);
    if (span == NULL)
        return;

    ngx_http_lua_opentelemetry_span_push(L, span);
    return;
}

static const char *ngx_http_lua_opentelemetry_span_start_headers_helper_value(const char *name, size_t name_len, size_t *value_len, void *arg)
{
    lua_State *L = arg;

    lua_pop(L, 1); /* remove result of the previous lua_gettable(), or the initial nil */
    lua_pushlstring(L, name, name_len);
    lua_gettable(L, -2);
    const char *value = lua_tolstring(L, -1, value_len);
    if (value == NULL || *value_len == 0)
        return NULL;
    /* we don't call lua_pop(L, 1) here as the value will be accessed by the caller */
    return value;
}

static void
ngx_http_lua_opentelemetry_span_start_headers_helper(lua_State *L, int headers, const char *operation_name, size_t operation_name_len) {

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    lua_rawgeti(L, LUA_REGISTRYINDEX, headers);
    lua_pushnil(L);
    opentelemetry_span *span = ngx_http_opentelemetry_span_start_headers(r, operation_name, operation_name_len, ngx_http_lua_opentelemetry_span_start_headers_helper_value, L);
    lua_pop(L, 2);
    if (span == NULL)
        return;

    ngx_http_lua_opentelemetry_span_push(L, span);
    return;
}

void
ngx_http_lua_opentelemetry_span_finish_helper(void *data) {
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_opentelemetry_is_enabled(r))
        return;

    opentelemetry_span *span = ngx_http_lua_opentelemetry_span_peek(L);
    if (!span)
        return;

    ngx_http_opentelemetry_span_finish(r, span);

    ngx_http_lua_opentelemetry_span_pop(L);
    return;
}

opentelemetry_span *
ngx_http_lua_opentelemetry_get_current_span(void *data)
{
    lua_State *L = (lua_State*)data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_opentelemetry_is_enabled(r))
        return NULL;

    return ngx_http_lua_opentelemetry_span_peek(L);
}

static int
ngx_http_lua_opentelemetry_is_enabled(lua_State *L) {
    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    lua_pushboolean(L, ngx_http_opentelemetry_is_enabled(r));
    return 1;
}

static int
ngx_http_lua_opentelemetry_span_start(lua_State *L) {
	lua_settop(L, 2);

    size_t operation_name_len;
    const char *operation_name = luaL_checklstring(L, 1, &operation_name_len);
    int ref_type = lua_type(L, 2);
    if (ref_type == LUA_TNIL) {
        ngx_http_lua_opentelemetry_span_start_helper(L, operation_name, operation_name_len);
        return 0;
    } else if (ref_type != LUA_TTABLE)
        return luaL_error(L, "the second argument must be a table");

    lua_pushvalue(L, 2);
    int headers = luaL_ref(L, LUA_REGISTRYINDEX);
    ngx_http_lua_opentelemetry_span_start_headers_helper(L, headers, operation_name, operation_name_len);
    luaL_unref(L, LUA_REGISTRYINDEX, headers);
    return 0;
}

bool
ngx_http_lua_opentelemetry_span_debug_helper(void *data) {
    lua_State *L = data;

    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_opentelemetry_is_enabled(r))
        return false;

    return ngx_http_opentelemetry_span_debug(r, ngx_http_lua_opentelemetry_span_peek(L));
}

static int
ngx_http_lua_opentelemetry_span_debug(lua_State *L) {
    lua_pushboolean(L, ngx_http_lua_opentelemetry_span_debug_helper(L));
    return 1;
}

static int ngx_http_lua_opentelemetry_header_get(const char *name, size_t name_len, const char *value, size_t value_len, void *arg) {
    lua_State *L = arg;

    lua_pushlstring(L, name, name_len);
    lua_pushlstring(L, value, value_len);
    lua_settable(L, -3);
    return 0;
}

static int
ngx_http_lua_opentelemetry_span_headers(lua_State *L) {
    ngx_http_request_t *r;
    r = ngx_http_lua_get_req(L);

    if (r == NULL) {
        luaL_error(L, "no request object found");
    }

    if (!ngx_http_opentelemetry_is_enabled(r))
        return 0;

    void *span = ngx_http_lua_opentelemetry_span_peek(L);
    if (!span)
        return 0;

    lua_newtable(L);
    if (ngx_http_opentelemetry_span_headers_get(r, span, ngx_http_lua_opentelemetry_header_get, L) < 0)
        return 0;
    return 1;
}

static int
ngx_http_lua_opentelemetry_span_finish(lua_State *L) {
    ngx_http_lua_opentelemetry_span_finish_helper(L);;
    return 0;
}

/* returns true if value which is at the top of the stack is replaced with the temporary one */
static bool
ngx_http_lua_opentelemetry_fill_attr(opentelemetry_attribute *attr, lua_State *L, const char *key, size_t key_len, void **extra)
{
    *extra = NULL;
    attr->name = (opentelemetry_string)OPENTELEMETRY_STR(key, key_len);
    int value_type = lua_type(L, -1);
    switch (value_type) {
    case LUA_TNIL:
        attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_CSTR("nil");
        return false;
    case LUA_TSTRING: {
        size_t value_len;
        const char *value = lua_tolstring(L, -1, &value_len);
        attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_STR(value, value_len);
        return false;
    }
    case LUA_TNUMBER: {
        lua_Number value = lua_tonumber(L, -1);
        attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_DOUBLE(value);
        return false;
    }
    case LUA_TBOOLEAN: {
        int value = lua_toboolean(L, -1);
        attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_BOOL(value);
        return false;
    }
    case LUA_TTABLE: {
        size_t len = lua_objlen(L, -1);

        if (len == 0)
            break;

        size_t nstrings = 0, nnumbers = 0, nbooleans = 0;
        size_t i;

        for (i = 0; i != len; i++) {
            lua_rawgeti(L, -1, i + 1);
            value_type = lua_type(L, -1);
            lua_pop(L, 1);
            switch (value_type) {
            case LUA_TSTRING: nstrings++; break;
            case LUA_TNUMBER: nnumbers++; break;
            case LUA_TBOOLEAN: nbooleans++; break;
            default: break;
            }
        }
        if (nnumbers == len) {
            double *values = malloc(len * sizeof(*values));
            if (values == NULL) {
                attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_CSTR("[fault]");
                return false;
            }
            *extra = values;
            for (i = 0; i != len; i++) {
                lua_rawgeti(L, -1, i + 1);
                lua_Number value = lua_tonumber(L, -1);
                lua_pop(L, 1);
                values[i] = value;
            }
            attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_ARRAY_DOUBLE(values, len);
            return false;
        } else if (nbooleans == len) {
            bool *values = malloc(len * sizeof(*values));
            if (values == NULL) {
                attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_CSTR("[fault]");
                return false;
            }
            *extra = values;
            for (i = 0; i != len; i++) {
                lua_rawgeti(L, -1, i + 1);
                int value = lua_toboolean(L, -1);
                lua_pop(L, 1);
                values[i] = value;
            }
            attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_ARRAY_BOOL(values, len);
            return false;
        } else {
            /* all the other cases will be converted to a string array */

            opentelemetry_string *values = malloc(len * sizeof(*values));
            if (values == NULL) {
                attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_CSTR("[fault]");
                return false;
            }
            *extra = values;

            int source_idx = -1;
            int tmp_idx = 1;
            if (nstrings != len) {
                /* Lua 5.1 doesn't have luaL_tolstring() function, so we'll just call lua's tostring() */
                lua_getglobal(L, "tostring");

                /* we have to create a temporary table to store values converted to strings */
                lua_createtable(L, len, 0);
                source_idx = -3;
            }
            for (i = 0; i != len; i++) {
                lua_rawgeti(L, source_idx, i + 1);
                value_type = (nstrings == len) ? LUA_TSTRING : lua_type(L, -1);
                if (value_type == LUA_TSTRING) {
                    values[i].ptr = lua_tolstring(L, -1, &values[i].len);
                    lua_pop(L, 1);
                    continue;
                }
                lua_pushvalue(L, -3);
                lua_pushvalue(L, -2);
                lua_call(L, 1, 1);
                /* stack: source, tostring, tmp_table, value, tostring_value */
                if (lua_type(L, -1) != LUA_TSTRING) {
                    lua_pop(L, 2);
                    values[i] = (opentelemetry_string)OPENTELEMETRY_CSTR("");
                    continue;
                }
                size_t value_len;
                const char *value = lua_tolstring(L, -1, &value_len);
                values[i] = (opentelemetry_string)OPENTELEMETRY_STR(value, value_len);
                lua_rawseti(L, -3, tmp_idx++);
                lua_pop(L, 1);
            }
            attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_ARRAY_STR(values, len);
            if (nstrings == len)
                return false;
            /* stack: source, tostring, tmp_table */
            lua_remove(L, -2);
            lua_remove(L, -2);
            return true;
        }
    }
    }

    /* Table or another type. We try to use tostring(). */

    /* Lua 5.1 doesn't have luaL_tolstring() function, so just call lua's tostring() */
    lua_getglobal(L, "tostring");
    lua_pushvalue(L, -2);
    lua_call(L, 1, 1);
    if (lua_type(L, -1) != LUA_TSTRING) {
        lua_pop(L, 1);
        attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_CSTR("");
        return false;
    }
    lua_remove(L, -2);
    size_t value_len;
    const char *value = lua_tolstring(L, -1, &value_len);
    attr->value = (opentelemetry_value)OPENTELEMETRY_VALUE_STR(value, value_len);
    return true;
}

static int
ngx_http_lua_opentelemetry_span_log(lua_State *L)
{
    opentelemetry_span *span = ngx_http_lua_opentelemetry_get_current_span(L);
    if (span == NULL)
        return 0;

    size_t key_len;
    const char *key = luaL_checklstring(L, 1, &key_len);
    if (key_len == 0)
        return 0;
    lua_settop(L, 2);
    opentelemetry_string name = OPENTELEMETRY_STR(NULL, 0);
    opentelemetry_attribute attr;
    void *extra;
    ngx_http_lua_opentelemetry_fill_attr(&attr, L, key, key_len, &extra);
    opentelemetry_span_add_event(span, &name, NULL, &attr, 1);
    if (extra != NULL)
        free(extra);

    return 0;
}

static int
ngx_http_lua_opentelemetry_span_event(lua_State *L)
{
    opentelemetry_span *span = ngx_http_lua_opentelemetry_get_current_span(L);
    if (span == NULL)
        return 0;

    lua_settop(L, 3);

    int table_idx;
    opentelemetry_string name = OPENTELEMETRY_STR(NULL, 0);
    if (lua_istable(L, 1))
        table_idx = 1;
    else {
        name.ptr = lua_tolstring(L, 1, &name.len);
        if (!lua_istable(L, 2)) {
            size_t key_len;
            const char *key = lua_tolstring(L, 2, &key_len);
            if (key == NULL || key_len == 0) {
                if (name.len != 0)
                    opentelemetry_span_add_event(span, &name, NULL, NULL, 0);
                return 0;
            }
            opentelemetry_attribute attr;
            void *extra;
            ngx_http_lua_opentelemetry_fill_attr(&attr, L, key, key_len, &extra);
            opentelemetry_span_add_event(span, &name, NULL, &attr, 1);
            if (extra != NULL)
                free(extra);
            return 0;
        }
        table_idx = 2;
    }

    /* TODO: use iterable opentelemetry_span_add_event interface, when it will be done */
    opentelemetry_attribute lattrs[32], *attrs = lattrs;
    size_t nattrs_allocated = sizeof(lattrs) / sizeof(lattrs[0]);
    size_t nattrs = 0;
    void *lextras[16], **extras = lextras;
    size_t nextras_allocated = sizeof(lextras) / sizeof(lextras[0]);
    size_t nextras = 0;

    lua_pushnil(L);
    while (lua_next(L, table_idx) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING) {
            lua_pop(L, 1);
            continue;
        }
        size_t key_len;
        const char *key = lua_tolstring(L, -2, &key_len);
        if (key == NULL || key_len == 0) {
            lua_pop(L, 1);
            continue;
        }
        if (nattrs == nattrs_allocated) {
            opentelemetry_attribute *attrs_new;

            nattrs_allocated *= 2;
            if (attrs == lattrs) {
                attrs_new = malloc(nattrs_allocated * sizeof(attrs[0]));
                if (attrs_new != NULL)
                    memcpy(attrs_new, attrs, nattrs * sizeof(attrs[0]));
            } else
                attrs_new = realloc(attrs, nattrs_allocated * sizeof(attrs[0]));

            if (attrs_new == NULL)
                goto fail;
            attrs = attrs_new;
        }
        if (nextras == nextras_allocated) {
            typeof(extras) extras_new;

            nextras_allocated *= 2;
            if (extras == lextras) {
                extras_new = malloc(nextras_allocated * sizeof(extras[0]));
                if (extras_new != NULL)
                    memcpy(extras_new, extras, nextras * sizeof(extras[0]));
            } else
                extras_new = realloc(extras, nextras_allocated * sizeof(extras[0]));

            if (extras_new == NULL)
                goto fail;
            extras = extras_new;
        }
        opentelemetry_attribute *attr = &attrs[nattrs++];
        bool fill_attr_rv = ngx_http_lua_opentelemetry_fill_attr(attr, L, key, key_len, &extras[nextras]);
        if (extras[nextras] != NULL)
            nextras++;
        if (!fill_attr_rv) {
            lua_pop(L, 1);
            continue;
        }
        /*
         * We now have a temporary value on the stack at index -1 instead of the
         * previous value, and the pointer to its data is stored in the attr. So,
         * we cannot remove the value. Swap key and value on the stack instead.
         */
        lua_pushvalue(L, -2);
        lua_remove(L, -3);
    }
    if (nattrs != 0 || name.len != 0)
        opentelemetry_span_add_event(span, &name, NULL, attrs, nattrs);

fail:
    ;
    size_t iextra;
    for (iextra = 0; iextra != nextras; iextra++)
        free(extras[iextra]);
    if (extras != lextras)
        free(extras);
    if (attrs != lattrs)
        free(attrs);
    return 0;
}

static int
ngx_http_lua_opentelemetry_span_attr(lua_State *L)
{
    opentelemetry_span *span = ngx_http_lua_opentelemetry_get_current_span(L);
    if (span == NULL)
        return 0;

    lua_settop(L, 2);

    if (!lua_istable(L, 1)) {
        size_t key_len;
        const char *key = lua_tolstring(L, -2, &key_len);
        if (key == NULL || key_len == 0)
            return 0;
        opentelemetry_attribute attr;
        void *extra;
        ngx_http_lua_opentelemetry_fill_attr(&attr, L, key, key_len, &extra);
        opentelemetry_span_set_attribute(span, &attr);
        if (extra != NULL)
            free(extra);
        return 0;
    }

    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        if (lua_type(L, -2) != LUA_TSTRING) {
            lua_pop(L, 1);
            continue;
        }
        size_t key_len;
        const char *key = lua_tolstring(L, -2, &key_len);
        if (key == NULL || key_len == 0) {
            lua_pop(L, 1);
            continue;
        }
        opentelemetry_attribute attr;
        void *extra;
        ngx_http_lua_opentelemetry_fill_attr(&attr, L, key, key_len, &extra);
        opentelemetry_span_set_attribute(span, &attr);
        if (extra != NULL)
            free(extra);
        lua_pop(L, 1);
    }

    return 0;
}

void
ngx_http_lua_inject_opentelemetry_api(lua_State *L)
{
    lua_createtable(L, 0, 1);

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_is_enabled);
    lua_setfield(L, -2, "is_enabled");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_start);
    lua_setfield(L, -2, "span_start");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_debug);
    lua_setfield(L, -2, "span_debug");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_headers);
    lua_setfield(L, -2, "span_headers");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_finish);
    lua_setfield(L, -2, "span_finish");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_event);
    lua_setfield(L, -2, "span_event");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_log);
    lua_setfield(L, -2, "span_log");

    lua_pushcfunction(L, ngx_http_lua_opentelemetry_span_attr);
    lua_setfield(L, -2, "span_attr");

    lua_setfield(L, -2, "tracing");
}
