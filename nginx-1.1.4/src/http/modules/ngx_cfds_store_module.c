#include <ngx_core.h>
#include <ngx_http.h>
#include <nginx.h>
#include <ngx_md5.h>

static char *ngx_cfds_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static ngx_int_t ngx_cfds_store_handler(ngx_http_request_t *r);

/* Commands */
static ngx_command_t ngx_cfds_store_commands[] = {
	{
		ngx_string("ngx_cfds_store"),
		NGX_HTTP_LOC_CONF|NGX_CONF_NOARGS,
		ngx_cfds_store,
		NGX_HTTP_LOC_CONF_OFFSET,
		0,
		NULL 
	},
	ngx_null_command
};

static ngx_http_module_t ngx_cfds_store_module_ctx = {
	NULL,                                  /* preconfiguration */
	NULL,                                  /* postconfiguration */

	NULL,                                  /* create main configuration */
	NULL,                                  /* init main configuration */

	NULL,                                  /* create server configuration */
	NULL,                                  /* merge server configuration */

	NULL,                                  /* create location configuration */
	NULL                                   /* merge location configuration */
};

/* hook */
ngx_module_t  ngx_cfds_store_module = {
	NGX_MODULE_V1,
	&ngx_cfds_store_module_ctx,            /* module context */
	ngx_cfds_store_commands,               /* module directives */
	NGX_HTTP_MODULE,                       /* module type */
	NULL,                                  /* init master */
	NULL,                                  /* init module */
	NULL,             		       /* init process */
	NULL,                                  /* init thread */
	NULL,                                  /* exit thread */
	NULL,             		       /* exit process */
	NULL,                                  /* exit master */
	NGX_MODULE_V1_PADDING
};

//size = 256
static unsigned int twHash(const char* str, int size) {
	unsigned int n = 0;
	int i;
	char *b = (char*)&n;
	int len = ngx_strlen(str);

	for (i=0; i<len; i++) {
		b[i%4] ^= str[i];
	}
	return n%size;
}

static int md5sum(char *dest, unsigned char *str) {
	MD5_CTX ctx;
	unsigned char *data = str;
	unsigned char md[16];
	char buf[33], tmp[3];
	memset(buf, 0, sizeof(buf));
	memset(tmp, 0, sizeof(tmp));
	int i;

	MD5_Init(&ctx);
	MD5_Update(&ctx, data, strlen(data));
	MD5_Final(md, &ctx);

	for(i=0; i<16; i++){
		sprintf(tmp, "%02x", md[i]);
		strcat(buf, tmp);
	}
	strcpy(dest, buf);
	return 0;
}

static int cfds_store_get_disk(ngx_http_request_t *r) {
	int sdisk = 0, status = 0, pos = 0;
	u_char *ptr, *start, *end;

	for (ptr = r->header_in->start; ptr < r->header_in->last; ptr++) {
		if (*ptr == '\n') {
			if (status == 0) {
				status = 1;
				start = ptr;
			} else {
				status = 0;
			}
		}

		if (*ptr == 'D') {
			if (status == 1) {
				status = 2;
			} else {
				status = 0;
			}
		}

		if (*ptr == '\0') {
			if (status == 2) {
				end = ptr;
				if ((end-start) < 4) {
					ptr += 1;
					sdisk = strtol(ptr, NULL, 10);
					break;
				} else {
					status = 0;
				}
			} else {
				status = 0;
			}
		}
	}

	if (!sdisk) {
		sdisk = 1;
	}
	return sdisk;
}

static ngx_int_t ngx_cfds_store_handler(ngx_http_request_t *r) 
{
	ngx_int_t rc;
	char out_buf[1024] = {0};
	char md5_buf[33] = {0};
	char md51[17] = {0}, md52[17] = {0}, *md5ptr = md5_buf;
	unsigned int dir1, dir2;

	if (!(r->method & NGX_HTTP_GET)) {
        return NGX_HTTP_NOT_ALLOWED;
    }

	FILE *pf;
	ngx_buf_t *b;
	ngx_chain_t out;
	char pbuf[1024] = {0};

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	rc = ngx_http_discard_request_body(r);

	if (rc != NGX_OK && rc != NGX_AGAIN) {
		return rc;
	}

	if (strstr(r->uri_start, "/CC_cfds_store_4_php/")) {
		r->headers_out.content_type.len = sizeof("text/html") - 1;
		r->headers_out.content_type.data = (u_char *) "text/html";

		if (r->method == NGX_HTTP_HEAD) {
			rc = ngx_http_send_header(r);

			if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
				return rc;
			}
		}

		if ((pf = popen("df -h | grep cache | awk \'{print $5\"\t\"$6}\'", "r")) == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		memset(pbuf, 0, sizeof(pbuf));
		fread(pbuf, sizeof(pbuf), sizeof(char), pf);
		pclose(pf);

		ngx_sprintf(out_buf, "%s", pbuf);

		b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
		if (b == NULL) {
			return NGX_HTTP_INTERNAL_SERVER_ERROR;
		}

		out.buf = b;
		out.next = NULL;

		b->pos = (u_char *)out_buf;
		b->last = (u_char *)out_buf + strlen(out_buf);
		b->memory = 1;
		b->last_buf = 1;
		r->headers_out.status = NGX_HTTP_OK;
		r->headers_out.content_length_n = strlen(out_buf);

		rc = ngx_http_send_header(r);

		if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
			return rc;
		}

		return ngx_http_output_filter(r, &out);

	} else {

		r->headers_out.content_type.len = sizeof("application/octet-stream") - 1;
		r->headers_out.content_type.data = (u_char *) "application/octet-stream";

		if (r->method == NGX_HTTP_HEAD) {
			rc = ngx_http_send_header(r);

			if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
				return rc;
			}
		}

		memset(out_buf, 0, sizeof(out_buf));

		ngx_memcpy(out_buf, "http://", 7);
		ngx_memcpy(out_buf + ngx_strlen(out_buf), r->headers_in.host->value.data, r->headers_in.host->value.len);
		ngx_memcpy(out_buf + ngx_strlen(out_buf), r->unparsed_uri.data, r->unparsed_uri.len);

		md5sum(md5_buf, out_buf);
		md5_buf[32] = '\0';

		ngx_memcpy(md51, md5ptr, 16);
		md51[16] = '\0';
		dir1 = twHash(md51, 256);

		ngx_memcpy(md52, (md5ptr+16), 16);
		md52[16] = '\0';
		dir2 = twHash(md52, 256);

		int sdisk = cfds_store_get_disk(r);

		memset(out_buf, 0, sizeof(out_buf));
		ngx_sprintf(out_buf, "/cache%d/cfds/store/%d/%d/%s.dat", sdisk, dir1, dir2, md5_buf);
		ngx_str_t ruri = ngx_string(out_buf);
		return ngx_http_internal_redirect(r, &ruri, NULL);
	}
}

static char * ngx_cfds_store(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {//Means this 
	ngx_http_core_loc_conf_t *clcf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
	clcf->handler = ngx_cfds_store_handler;
	return NGX_CONF_OK;
}
