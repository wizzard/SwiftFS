#include <event2/event.h>
#include <event2/dns.h>
#include <event2/bufferevent.h>
#include <event2/bufferevent_struct.h>
#include <event2/bufferevent_ssl.h>
#include <event2/http.h>
#include <event2/http_struct.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <assert.h>

#define HOST "127.0.0.1"
#define PORT 443

struct event_base *evbase;
struct evdns_base *dnsbase;

static void on_connection_close (struct evhttp_connection * c, void * arg)
{
	fprintf (stderr, "connection closed\n");
}

static void on_response_cb (struct evhttp_request * req, void * arg)
{
    if (!req) {
	    fprintf (stderr, "Response == NULL ! \n");
    }

	fprintf (stderr, "Ok\n");
}

static int SSLX_CTX_verify_callback(int unused, X509_STORE_CTX *ctx)
{
	fprintf (stderr, "SSLX_CTX_verify_callback \n");
	return 1;
}


static void perform_ssl_connection (void)
{
    struct evhttp_connection *con;
    struct evhttp_request *req;
    struct bufferevent *bev;
    SSL_CTX *sctx;
    SSL *ssl;

    sctx = SSL_CTX_new (SSLv23_client_method ());
    assert (sctx);

    SSL_CTX_set_options (sctx, SSL_OP_NO_TLSv1_2);
	//SSL_CTX_set_options (sctx, SSL_OP_ALL);
	SSL_CTX_set_timeout (sctx, 3000);
	SSL_CTX_set_verify (sctx, SSL_VERIFY_PEER, SSLX_CTX_verify_callback);
	SSL_CTX_set_default_verify_paths (sctx);
    SSL_CTX_set_cipher_list (sctx, "RC4-MD5");

    ssl = SSL_new (sctx);
    assert (ssl);

     bev = bufferevent_openssl_socket_new (evbase, -1, ssl, BUFFEREVENT_SSL_CONNECTING , BEV_OPT_CLOSE_ON_FREE);
    //bev = bufferevent_socket_new (evbase, -1, BEV_OPT_CLOSE_ON_FREE);
    assert (bev);

    con = evhttp_connection_base_bufferevent_new (evbase, dnsbase, bev, HOST, PORT);
    evhttp_connection_set_closecb (con, on_connection_close, NULL);
    evhttp_connection_set_timeout (con, 10);

	req = evhttp_request_new (on_response_cb, NULL);
	evhttp_add_header (req->output_headers, "Host", HOST);
//	evhttp_add_header (req->output_headers, "Connection", "Keep-Alive");

    evhttp_make_request (con, req, EVHTTP_REQ_GET, "/index.html");
}

int main ()
{

	SSL_library_init ();
	ERR_load_crypto_strings ();
	SSL_load_error_strings ();
	OpenSSL_add_all_algorithms();

    event_enable_debug_mode ();
    evbase = event_base_new ();
    dnsbase = evdns_base_new (evbase, 1);

    perform_ssl_connection ();

    event_base_dispatch (evbase);
    event_base_free (evbase);

    return 0;
}
