/*
 * (C) 2009
*/
#include <ngx_config.h>
#include <ngx_core.h> 
#include <ngx_http.h>

typedef struct {
	ngx_str_t	file_path_variable_name;
} ngx_http_check_mtime_conf_t;

/* Variable handlers */
static char *ngx_http_check_mtime_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_http_check_mtime_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data);
static ngx_command_t ngx_http_check_mtime_commands[] = {
	{
		ngx_string("check_mtime"),
		NGX_HTTP_SRV_CONF|NGX_HTTP_SIF_CONF|NGX_HTTP_LOC_CONF|NGX_HTTP_LIF_CONF|NGX_CONF_TAKE2,
		ngx_http_check_mtime_init,
		0,
		0,
		NULL
	},
	ngx_null_command
};

static ngx_http_module_t ngx_http_check_mtime_module_ctx = {
	NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

ngx_module_t ngx_http_check_mtime_module = {
	NGX_MODULE_V1,
	&ngx_http_check_mtime_module_ctx, /* module context */
	ngx_http_check_mtime_commands, /* module directives */
	NGX_HTTP_MODULE, /* module type */
	NULL, /* init master */
	NULL, /* init module */
	NULL, /* init process */
	NULL, /* init thread */
	NULL, /* exit thread */
	NULL, /* exit process */
	NULL, /* exit master */
	NGX_MODULE_V1_PADDING
};

static char * ngx_http_check_mtime_init(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
	ngx_str_t *check_mtime_vars;
	ngx_http_variable_t *resultVariable;
	check_mtime_vars = cf->args->elts;

	/* TODO some more validations & checks */
	if (check_mtime_vars[2].data[0] != '$') {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_mtime_module: invalid parameter: \"%s\"", check_mtime_vars[2].data);
		return NGX_CONF_ERROR;
	}
	check_mtime_vars[2].len--;
	check_mtime_vars[2].data++;
	resultVariable = ngx_http_add_variable(cf, &check_mtime_vars[2], NGX_HTTP_VAR_CHANGEABLE);
	if (resultVariable == NULL) {
		ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_mtime_module: cannot add variable: \"%s\"", check_mtime_vars[2].data);
		return NGX_CONF_ERROR;
	}
	if (resultVariable->get_handler == NULL ) {
		resultVariable->get_handler = ngx_http_check_mtime_variable;
 
		ngx_http_check_mtime_conf_t  *check_mtime_conf;
		check_mtime_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_check_mtime_conf_t));
		if (check_mtime_conf == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_mtime_module: allocation failed");
			return NGX_CONF_ERROR;
		}

		if (check_mtime_vars[1].data[0] != '$') {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_mtime_module: invalid parameter: \"%s\"", check_mtime_vars[1].data);
			return NGX_CONF_ERROR;
		}
		check_mtime_vars[1].len--;
		check_mtime_vars[1].data++;
		check_mtime_conf->file_path_variable_name.len = check_mtime_vars[1].len;
		check_mtime_conf->file_path_variable_name.data = ngx_palloc(cf->pool, check_mtime_vars[1].len + 1);
		if (check_mtime_conf->file_path_variable_name.data == NULL) {
			ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "check_mtime_module: allocation failed");
			return NGX_CONF_ERROR;
		}
		ngx_cpystrn(check_mtime_conf->file_path_variable_name.data, check_mtime_vars[1].data, check_mtime_vars[1].len + 1);

		resultVariable->data = (uintptr_t) check_mtime_conf;
	}
	return NGX_CONF_OK;
}

static ngx_int_t ngx_http_check_mtime_variable(ngx_http_request_t *r, ngx_http_variable_value_t *v, uintptr_t data) {
	ngx_http_check_mtime_conf_t  *check_mtime_conf = (ngx_http_check_mtime_conf_t *) data;

	/* Reset variable */
	v->valid = 0;
	v->not_found = 1;
	if (check_mtime_conf == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: runtime error \"data\" is NULL");
		return NGX_OK;
	}
	
	// Evaluate date variable
	ngx_http_variable_value_t  *file_path_variable;
	ngx_uint_t key = ngx_hash_strlow(check_mtime_conf->file_path_variable_name.data, check_mtime_conf->file_path_variable_name.data, check_mtime_conf->file_path_variable_name.len);
	file_path_variable = ngx_http_get_variable(r, &check_mtime_conf->file_path_variable_name, key);
	if (file_path_variable == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: invalid variable '$%s'", check_mtime_conf->file_path_variable_name.data);
		return NGX_OK;
	}
	if (file_path_variable->not_found) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: variable not found '%s'", check_mtime_conf->file_path_variable_name.data);
		return NGX_OK;
	}
	if (file_path_variable->len == 0){
		return NGX_OK;
	}
	ngx_file_info_t fi;

	/* Copy file_path_variable into new variable */
	ngx_str_t new_file_path_variable;
	new_file_path_variable.len = file_path_variable->len;
	new_file_path_variable.data = ngx_pnalloc(r->pool, new_file_path_variable.len + 1);
	if (new_file_path_variable.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: allocation failed");
		return NGX_OK;
	}
	ngx_cpystrn(new_file_path_variable.data, file_path_variable->data, new_file_path_variable.len + 1);
	new_file_path_variable.data[new_file_path_variable.len] = '\0';

	if (ngx_file_info((const char *) new_file_path_variable.data, &fi) == -1) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: cannot get file info '%s'", new_file_path_variable.data);
		return NGX_OK;
	}
	if (!ngx_is_file(&fi)) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: '%s' is not a file", new_file_path_variable.data);
		return NGX_OK;
	}
	time_t mtime = ngx_file_mtime(&fi);
	time_t local_time = time(NULL);

	// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "FILE : %s", file_path_variable->data);
	// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "MTIME : %i", mtime);
	// ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "TIME: %i", local_time);

	ngx_str_t time_interval = ngx_string("");
	time_interval.len = 10;
	time_interval.data = ngx_pnalloc(r->pool, time_interval.len + 1);
	if (time_interval.data == NULL) {
		ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "check_mtime_module: allocation failed");
		return NGX_OK;
	}
	ngx_sprintf(time_interval.data, "%i", local_time - mtime);
	time_interval.len = ngx_strlen(time_interval.data);

	// Set return value
	v->data = time_interval.data;
	v->len = ngx_strlen( v->data );
	v->valid = 1;
	v->no_cacheable = 0;
	v->not_found = 0;
	ngx_log_debug(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "check_mtime_module: Result: '%s'", v->data);
	return NGX_OK;
}