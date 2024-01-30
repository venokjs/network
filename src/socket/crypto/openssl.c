#ifndef VENOK_NO_SSL

/* This module contains the entire OpenSSL implementation
 * of the SSL socket and socket context interfaces. */
#include <openssl/bio.h>
#include <openssl/dh.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

#include <string.h>

#include "v_socket.h"
#include "../internal/internal.h"
#include "./sni_tree.h"
#include "./root_certs.h"

static X509 *root_cert_instances[sizeof(root_certs) / sizeof(root_certs[0])] = {
        NULL};

/* These are in root_certs.cpp */
extern X509_STORE *v_get_default_ca_store();


struct loop_ssl_data {
    char *ssl_read_input, *ssl_read_output;
    unsigned int ssl_read_input_length;
    unsigned int ssl_read_input_offset;

    struct v_socket *ssl_socket;

    int last_write_was_msg_more;
    int msg_more;

    BIO *shared_rbio;
    BIO *shared_wbio;
    BIO_METHOD *shared_biom;
};

struct v_ssl_socket_context {
    struct v_socket_context sc;

    /* This thing can be shared with other socket contexts via socket transfer!
     * maybe instead of holding once you hold many, a vector or set
     * when a socket that belongs to another socket context transfers to a new socket context*/
    SSL_CTX *ssl_context;
    int is_parent;

    /* These decorate the base implementation */
    struct v_ssl_socket *(*on_open)(struct v_ssl_socket *, int is_client, char *ip, int ip_length);
    struct v_ssl_socket *(*on_data)(struct v_ssl_socket *, char *data, int length);
    struct v_ssl_socket *(*on_writable)(struct v_ssl_socket *);
    struct v_ssl_socket *(*on_close)(struct v_ssl_socket *, int code, void *reason);

    /* Called for missing SNI hostnames, if not NULL */
    void (*on_server_name)(struct v_ssl_socket_context *, const char *hostname);

    /* Pointer to sni tree, created when the context is created and freed likewise when freed */
    void *sni;
};

// same here, should or shouldn't it contain s?
struct v_ssl_socket {
    struct v_socket s;
    SSL *ssl;
    int ssl_write_wants_read; // we use this for now
    int ssl_read_wants_write;
};

int passphrase_cb(char *buf, int size, int rwflag, void *u) {
    const char *passphrase = (const char *) u;
    size_t passphrase_length = strlen(passphrase);
    memcpy(buf, passphrase, passphrase_length);
    // put null at end? no?
    return (int) passphrase_length;
}

/* Helper functions for loop init */
int BIO_s_custom_create(BIO *bio) {
    BIO_set_init(bio, 1);
    return 1;
}

long BIO_s_custom_ctrl(BIO *bio, int cmd, long num, void *user) {
    switch (cmd) {
        case BIO_CTRL_FLUSH:
            return 1;
        default:
            return 0;
    }
}

int BIO_s_custom_write(BIO *bio, const char *data, int length) {
    struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) BIO_get_data(bio);

    loop_ssl_data->last_write_was_msg_more = loop_ssl_data->msg_more || length == 16413;
    int written = v_socket_write(0, loop_ssl_data->ssl_socket, data, length, loop_ssl_data->last_write_was_msg_more);

    if (!written) {
        BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_WRITE);
        return -1;
    }

    return written;
}

int BIO_s_custom_read(BIO *bio, char *dst, int length) {
    struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) BIO_get_data(bio);

    if (!loop_ssl_data->ssl_read_input_length) {
        BIO_set_flags(bio, BIO_FLAGS_SHOULD_RETRY | BIO_FLAGS_READ);
        return -1;
    }

    if ((unsigned int) length > loop_ssl_data->ssl_read_input_length) {
        length = loop_ssl_data->ssl_read_input_length;
    }

    memcpy(dst, loop_ssl_data->ssl_read_input + loop_ssl_data->ssl_read_input_offset, length);

    loop_ssl_data->ssl_read_input_offset += length;
    loop_ssl_data->ssl_read_input_length -= length;
    return length;
}

/* Internal SSL callbacks */

struct v_ssl_socket *ssl_on_open(struct v_ssl_socket *s, int is_client, char *ip, int ip_length) {
    struct v_ssl_socket_context *context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

    struct v_loop *loop = v_socket_context_loop(0, &context->sc);
    struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) loop->data.ssl_data;

    s->ssl = SSL_new(context->ssl_context);
    s->ssl_write_wants_read = 0;
    s->ssl_read_wants_write = 0;
    SSL_set_bio(s->ssl, loop_ssl_data->shared_rbio, loop_ssl_data->shared_wbio);

    BIO_up_ref(loop_ssl_data->shared_rbio);
    BIO_up_ref(loop_ssl_data->shared_wbio);

    if (is_client) SSL_set_connect_state(s->ssl);
    else SSL_set_accept_state(s->ssl);

    return (struct v_ssl_socket *) context->on_open(s, is_client, ip, ip_length);
}

struct v_ssl_socket *v_ssl_socket_close(struct v_ssl_socket *s, int code, void *reason) {
    return (struct v_ssl_socket *) v_socket_close(0, (struct v_socket *) s, code, reason);
}

struct v_ssl_socket *ssl_on_close(struct v_ssl_socket *s, int code, void *reason) {
    struct v_ssl_socket_context *context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);
    SSL_free(s->ssl);
    return context->on_close(s, code, reason);
}

struct v_ssl_socket *ssl_on_end(struct v_ssl_socket *s) {
    /* Whatever state we are in, a TCP FIN is always an answered shutdown*/
    /* Todo: this should report CLEANLY SHUTDOWN as reason */
    return v_ssl_socket_close(s, 0, NULL);
}

// this whole function needs a complete clean-up
struct v_ssl_socket *ssl_on_data(struct v_ssl_socket *s, void *data, int length) {
    /* Note: this context can change when we adopt the socket!*/
    struct v_ssl_socket_context *context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

    struct v_loop *loop = v_socket_context_loop(0, &context->sc);
    struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) loop->data.ssl_data;

    /* Note: if we put data here we should never really clear it
     * (not in write either, it still should be available for SSL_write to read from!)
     */
    loop_ssl_data->ssl_read_input = data;
    loop_ssl_data->ssl_read_input_length = length;
    loop_ssl_data->ssl_read_input_offset = 0;
    loop_ssl_data->ssl_socket = &s->s;
    loop_ssl_data->msg_more = 0;

    if (v_socket_is_closed(0, &s->s)) return s;

    if (v_ssl_socket_is_shutdown(s)) {
        int ret;

        if ((ret = SSL_shutdown(s->ssl)) == 1) {
            /* Two phase shutdown is complete here*/
            /* Todo: this should also report some kind of clean shutdown */
            return v_ssl_socket_close(s, 0, NULL);
        } else if (ret < 0) {

            int err = SSL_get_error(s->ssl, ret);

            if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL) {
                /* We need to clear the error queue in case
                 * these added to the thread local queue
                 */
                ERR_clear_error();
            }
        }

        /* No further processing of data when in shutdown state */
        return s;
    }

    /* Bug checking: this loop needs a lot of attention and clean-ups and check-ups */
    int read = 0;
    restart:
    while (1) {
        int just_read = SSL_read(s->ssl, loop_ssl_data->ssl_read_output + VENOK_RECV_BUFFER_PADDING + read,
                                 VENOK_RECV_BUFFER_LENGTH - read);

        if (just_read <= 0) {
            int err = SSL_get_error(s->ssl, just_read);

            // as far as I know these are the only errors we want to handle
            if (err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {

                if (err == SSL_ERROR_ZERO_RETURN) {
                    /* Zero return can be EOF/FIN, if we have data just signal on_data and close */
                    if (read) {
                        context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

                        s = context->on_data(s, loop_ssl_data->ssl_read_output + VENOK_RECV_BUFFER_PADDING, read);

                        if (v_socket_is_closed(0, &s->s)) return s;
                    }
                    /* Terminate connection here */
                    return v_ssl_socket_close(s, 0, NULL);
                }

                /* Clear per thread error queue if it may contain something*/
                if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL) ERR_clear_error();

                /* Terminate connection here */
                return v_ssl_socket_close(s, 0, NULL);
            } else {
                /* Emit the data we have and exit
                 * here we need to trigger writable event next ssl_read!
                 */
                if (err == SSL_ERROR_WANT_WRITE) s->ssl_read_wants_write = 1;

                /* Assume we emptied the input buffer fully or error here as well!*/
                if (loop_ssl_data->ssl_read_input_length) return v_ssl_socket_close(s, 0, NULL);

                /* Cannot emit zero length to app*/
                if (!read) break;

                context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

                s = context->on_data(s, loop_ssl_data->ssl_read_output + VENOK_RECV_BUFFER_PADDING, read);

                if (v_socket_is_closed(0, &s->s)) return s;

                break;
            }

        }

        read += just_read;

        /* At this point we might be full and need to emit the data to application and start over */
        if (read == VENOK_RECV_BUFFER_LENGTH) {

            context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

            /* Emit data and restart */
            s = context->on_data(s, loop_ssl_data->ssl_read_output + VENOK_RECV_BUFFER_PADDING, read);
            if (v_socket_is_closed(0, &s->s)) return s;

            read = 0;
            goto restart;
        }
    }

    /* Trigger writable if we failed last write with want read */
    if (s->ssl_write_wants_read) {
        s->ssl_write_wants_read = 0;

        /* Make sure to update context before we call
         * (context can change if the user adopts the socket!)
         */
        context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

        s = (struct v_ssl_socket *) context->sc.on_writable(&s->s); /* Cast here!*/

        /* If we are closed here, then exit*/
        if (v_socket_is_closed(0, &s->s)) return s;
    }

    /* Check this then?*/
    if (SSL_get_shutdown(s->ssl) & SSL_RECEIVED_SHUTDOWN) {
        /* TODO: not correct anyway!*/
        s = v_ssl_socket_close(s, 0, NULL);
    }

    return s;
}

struct v_ssl_socket *ssl_on_writable(struct v_ssl_socket *s) {
    struct v_ssl_socket_context *context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

    /* Todo: cork here so that we efficiently output both from reading and from writing?*/
    if (s->ssl_read_wants_write) {
        s->ssl_read_wants_write = 0;

        /* Make sure to update context before we call
         * (context can change if the user adopts the socket!)
         */
        context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

        /* If this one fails to write data, it sets ssl_read_wants_write again */
        s = (struct v_ssl_socket *) context->sc.on_data(&s->s, 0, 0); // cast here!
    }

    /* Should this one come before we have read? should it come always? spurious on_writable is okay */
    s = context->on_writable(s);

    return s;
}

/* Lazily inits loop ssl data first time */
void v_init_loop_ssl_data(struct v_loop *loop) {
    if (!loop->data.ssl_data) {
        struct loop_ssl_data *loop_ssl_data = malloc(sizeof(struct loop_ssl_data));
        loop_ssl_data->ssl_read_input_length = 0;
        loop_ssl_data->ssl_read_input_offset = 0;
        loop_ssl_data->last_write_was_msg_more = 0;
        loop_ssl_data->msg_more = 0;

        loop_ssl_data->ssl_read_output = malloc(VENOK_RECV_BUFFER_LENGTH + VENOK_RECV_BUFFER_PADDING * 2);

        OPENSSL_init_ssl(0, NULL);

        loop_ssl_data->shared_biom = BIO_meth_new(BIO_TYPE_MEM, "VENOK BIO");
        BIO_meth_set_create(loop_ssl_data->shared_biom, BIO_s_custom_create);
        BIO_meth_set_write(loop_ssl_data->shared_biom, BIO_s_custom_write);
        BIO_meth_set_read(loop_ssl_data->shared_biom, BIO_s_custom_read);
        BIO_meth_set_ctrl(loop_ssl_data->shared_biom, BIO_s_custom_ctrl);

        loop_ssl_data->shared_rbio = BIO_new(loop_ssl_data->shared_biom);
        loop_ssl_data->shared_wbio = BIO_new(loop_ssl_data->shared_biom);
        BIO_set_data(loop_ssl_data->shared_rbio, loop_ssl_data);
        BIO_set_data(loop_ssl_data->shared_wbio, loop_ssl_data);

        loop->data.ssl_data = loop_ssl_data;
    }
}

/* Called by loop free, clears any loop ssl data */
void v_free_loop_ssl_data(struct v_loop *loop) {
    struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) loop->data.ssl_data;

    if (loop_ssl_data) {
        free(loop_ssl_data->ssl_read_output);

        BIO_free(loop_ssl_data->shared_rbio);
        BIO_free(loop_ssl_data->shared_wbio);

        BIO_meth_free(loop_ssl_data->shared_biom);

        free(loop_ssl_data);
    }
}

/* We throttle reading data for ssl sockets that are in init state. 
 * Here we actually use the kernel buffering to our advantage
 */
int ssl_is_low_prio(struct v_ssl_socket *s) {
    /* We use SSL_in_before() instead of SSL_in_init(), because only the first step is CPU intensive, and we want to
     * speed up the rest of connection establishing if the CPU intensive work is already done, so fully established
     * connections increase linearly over time under high load */
    return SSL_in_init(s->ssl);
}

/* Per-context functions */
void *v_ssl_socket_context_get_native_handle(struct v_ssl_socket_context *context) {
    return context->ssl_context;
}

struct v_ssl_socket_context *v_create_child_ssl_socket_context(struct v_ssl_socket_context *context, int context_ext_size) {
    /* Create a new non-SSL context */
    struct v_socket_context_options options = {0};
    struct v_ssl_socket_context *child_context =
            (struct v_ssl_socket_context *) v_create_socket_context(0, context->sc.loop,
                                                                    sizeof(struct v_ssl_socket_context) + context_ext_size, options);

    /* The only thing we share is SSL_CTX */
    child_context->ssl_context = context->ssl_context;
    child_context->is_parent = 0;

    return child_context;
}

/* Common function for creating a context from options.
 * We must NOT free an SSL_CTX with only SSL_CTX_free! Also free any password
 */
void free_ssl_context(SSL_CTX *ssl_context) {
    if (!ssl_context) return;

    /* If we have set a password string, free it here */
    void *password = SSL_CTX_get_default_passwd_cb_userdata(ssl_context);
    /* OpenSSL returns NULL if we have no set password */
    free(password);

    SSL_CTX_free(ssl_context);
}

/* Helper functions for creating context options */

int v_ssl_ctx_use_privatekey_content(SSL_CTX *ctx, const char *content, int type) {
    int reason_code, ret = 0;
    BIO *in;
    EVP_PKEY *pkey = NULL;
    in = BIO_new_mem_buf(content, strlen(content));

    if (in == NULL) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
        goto end;
    }

    if (type == SSL_FILETYPE_PEM) {
        reason_code = ERR_R_PEM_LIB;
        pkey = PEM_read_bio_PrivateKey(in, NULL, SSL_CTX_get_default_passwd_cb(ctx), SSL_CTX_get_default_passwd_cb_userdata(ctx));
    } else if (type == SSL_FILETYPE_ASN1) {
        reason_code = ERR_R_ASN1_LIB;
        pkey = d2i_PrivateKey_bio(in, NULL);
    } else {
        OPENSSL_PUT_ERROR(SSL, SSL_R_BAD_SSL_FILETYPE);
        goto end;
    }

    if (pkey == NULL) {
        OPENSSL_PUT_ERROR(SSL, reason_code);
        goto end;
    }

    ret = SSL_CTX_use_PrivateKey(ctx, pkey);
    EVP_PKEY_free(pkey);

    end:
    BIO_free(in);
    return ret;
}

int add_ca_cert_to_ctx_store(SSL_CTX *ctx, const char *content, X509_STORE *store) {
    X509 *x = NULL;
    BIO *in;

    /* Clear error stack for SSL_CTX_use_certificate() */
    ERR_clear_error();

    in = BIO_new_mem_buf(content, strlen(content));
    if (in == NULL) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
        goto end;
    }

    int count = 0;

    while ((x = PEM_read_bio_X509(in, NULL, SSL_CTX_get_default_passwd_cb(ctx), SSL_CTX_get_default_passwd_cb_userdata(ctx)))) {
        X509_STORE_add_cert(store, x);

        if (!SSL_CTX_add_client_CA(ctx, x)) {
            X509_free(x);
            BIO_free(in);
            return 0;
        }
        count++;
        X509_free(x);
    }

    end:
    BIO_free(in);

    return count > 0;
}

int v_ssl_ctx_use_certificate_chain(SSL_CTX *ctx, const char *content) {
    BIO *in;
    int ret = 0;
    X509 *x = NULL;

    /* Clear error stack for SSL_CTX_use_certificate() */
    ERR_clear_error();

    in = BIO_new_mem_buf(content, strlen(content));
    if (in == NULL) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_BUF_LIB);
        goto end;
    }

    x = PEM_read_bio_X509_AUX(in, NULL, SSL_CTX_get_default_passwd_cb(ctx),
                              SSL_CTX_get_default_passwd_cb_userdata(ctx));
    if (x == NULL) {
        OPENSSL_PUT_ERROR(SSL, ERR_R_PEM_LIB);
        goto end;
    }

    ret = SSL_CTX_use_certificate(ctx, x);

    /* Key/certificate mismatch doesn't imply ret==0 ... */
    if (ERR_peek_error() != 0) ret = 0;


    if (ret) {
        /* If we could set up our certificate, now proceed to the CA certificates */
        X509 *ca;
        int r;
        uint32_t err;

        SSL_CTX_clear_chain_certs(ctx);

        while ((ca = PEM_read_bio_X509(
                in, NULL, SSL_CTX_get_default_passwd_cb(ctx),
                SSL_CTX_get_default_passwd_cb_userdata(ctx))) != NULL) {
            r = SSL_CTX_add0_chain_cert(ctx, ca);

            if (!r) {
                X509_free(ca);
                ret = 0;
                goto end;
            }
            /* Note that we must not free r if it was successfully added to the chain
             * (while we must free the main certificate, since its reference count is
             * increased by SSL_CTX_use_certificate).
             */
        }

        /* When the while loop ends, it's usually just EOF */
        err = ERR_peek_last_error();
        if (ERR_GET_LIB(err) == ERR_LIB_PEM &&
            ERR_GET_REASON(err) == PEM_R_NO_START_LINE) {
            ERR_clear_error();
        } else {
            ret = 0; // some real error
        }
    }

    end:
    X509_free(x);
    BIO_free(in);
    return ret;
}

int v_verify_callback(int preverify_ok, X509_STORE_CTX *ctx) {
    /* From https://www.openssl.org/docs/man1.1.1/man3/SSL_verify_cb:
     *
     * If VerifyCallback returns 1, the verification process is continued.
     * If VerifyCallback always returns 1, the TLS/SSL handshake will not be
     * terminated with respect to verification failures and the connection will
     * be established. The calling process can however retrieve the error code
     * of the last verification error using SSL_get_verify_result(3) or by
     * maintaining its own error storage managed by VerifyCallback.
     *
     * Since we cannot perform I/O quickly enough with X509_STORE_CTX_ APIs in
     * this callback, we ignore all preverify_ok errors and let the handshake
     * continue. It is imperative that the user use Connection::VerifyError
     * after the 'secure' callback has been made.
     */
    return 1;
}

SSL_CTX *create_ssl_context_from_options(struct v_socket_context_options options) {
    /* Create the context */
    SSL_CTX *ssl_context = SSL_CTX_new(TLS_method());

    /* Default options we rely on - changing these will break our logic */
    SSL_CTX_set_read_ahead(ssl_context, 1);
    SSL_CTX_set_mode(ssl_context, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Anything below TLS 1.2 is disabled */
    SSL_CTX_set_min_proto_version(ssl_context, TLS1_2_VERSION);

    /* The following are helpers. You may easily implement whatever you want by
     * using the native handle directly */

    /* Important option for lowering memory usage, but lowers performance slightly
     */
    if (options.ssl_prefer_low_memory_usage) SSL_CTX_set_mode(ssl_context, SSL_MODE_RELEASE_BUFFERS);

    if (options.passphrase) {
        /* When freeing the CTX we need to check
         * SSL_CTX_get_default_passwd_cb_userdata and free it if set */
        SSL_CTX_set_default_passwd_cb_userdata(ssl_context, (void *) strdup(options.passphrase));
        SSL_CTX_set_default_passwd_cb(ssl_context, passphrase_cb);
    }

    /* This one most probably do not need the cert_file_name string to be kept
     * alive */
    if (options.cert_file_name) {
        if (SSL_CTX_use_certificate_chain_file(ssl_context, options.cert_file_name) != 1) {
            free_ssl_context(ssl_context);
            return NULL;
        }
    } else if (options.cert && options.cert_count > 0) {
        for (unsigned int i = 0; i < options.cert_count; i++) {
            if (v_ssl_ctx_use_certificate_chain(ssl_context, options.cert[i]) != 1) {
                free_ssl_context(ssl_context);
                return NULL;
            }
        }
    }

    /* Same as above - we can discard this string afterward I suppose */
    if (options.key_file_name) {
        if (SSL_CTX_use_PrivateKey_file(ssl_context, options.key_file_name, SSL_FILETYPE_PEM) != 1) {
            free_ssl_context(ssl_context);
            return NULL;
        }
    } else if (options.key && options.key_count > 0) {
        for (unsigned int i = 0; i < options.key_count; i++) {
            if (v_ssl_ctx_use_privatekey_content(ssl_context, options.key[i], SSL_FILETYPE_PEM) != 1) {
                free_ssl_context(ssl_context);
                return NULL;
            }
        }
    }

    if (options.ca_file_name) {
        SSL_CTX_set_cert_store(ssl_context, v_get_default_ca_store());

        STACK_OF(X509_NAME) *ca_list;
        ca_list = SSL_load_client_CA_file(options.ca_file_name);

        if (ca_list == NULL) {
            free_ssl_context(ssl_context);
            return NULL;
        }

        SSL_CTX_set_client_CA_list(ssl_context, ca_list);
        if (SSL_CTX_load_verify_locations(ssl_context, options.ca_file_name, NULL) != 1) {
            free_ssl_context(ssl_context);
            return NULL;
        }

        if (options.reject_unauthorized) {
            SSL_CTX_set_verify(ssl_context,
                               SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                               v_verify_callback);
        } else {
            SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, v_verify_callback);
        }

    } else if (options.ca && options.ca_count > 0) {
        X509_STORE *cert_store = NULL;

        for (unsigned int i = 0; i < options.ca_count; i++) {
            if (cert_store == NULL) {
                cert_store = v_get_default_ca_store();
                SSL_CTX_set_cert_store(ssl_context, cert_store);
            }

            if (!add_ca_cert_to_ctx_store(ssl_context, options.ca[i], cert_store)) {
                free_ssl_context(ssl_context);
                return NULL;
            }

            if (options.reject_unauthorized) {
                SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, v_verify_callback);
            } else {
                SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, v_verify_callback);
            }
        }
    } else {
        if (options.request_cert) {
            SSL_CTX_set_cert_store(ssl_context, v_get_default_ca_store());

            if (options.reject_unauthorized) {
                SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, v_verify_callback);
            } else {
                SSL_CTX_set_verify(ssl_context, SSL_VERIFY_PEER, v_verify_callback);
            }
        }
    }
    if (options.dh_params_file_name) {
        /* Set up ephemeral DH parameters. */
        DH *dh_2048 = NULL;
        FILE *paramfile;
        paramfile = fopen(options.dh_params_file_name, "r");

        if (paramfile) {
            dh_2048 = PEM_read_DHparams(paramfile, NULL, NULL, NULL);
            fclose(paramfile);
        } else {
            free_ssl_context(ssl_context);
            return NULL;
        }

        if (dh_2048 == NULL) {
            free_ssl_context(ssl_context);
            return NULL;
        }

        const long set_tmp_dh = SSL_CTX_set_tmp_dh(ssl_context, dh_2048);
        DH_free(dh_2048);

        if (set_tmp_dh != 1) {
            free_ssl_context(ssl_context);
            return NULL;
        }

        /* OWASP Cipher String 'A+'
         * (https://www.owasp.org/index.php/TLS_Cipher_String_Cheat_Sheet)
         */
        if (SSL_CTX_set_cipher_list(
                ssl_context,
                "DHE-RSA-AES256-GCM-SHA384:DHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-"
                "AES256-GCM-SHA384:ECDHE-RSA-AES128-GCM-SHA256") != 1) {
            free_ssl_context(ssl_context);
            return NULL;
        }
    }

    if (options.ssl_ciphers) {
        if (SSL_CTX_set_cipher_list(ssl_context, options.ssl_ciphers) != 1) {
            free_ssl_context(ssl_context);
            return NULL;
        }
    }

    if (options.secure_options) {
        SSL_CTX_set_options(ssl_context, options.secure_options);
    }

    /* This must be free's with free_ssl_context, not SSL_CTX_free */
    return ssl_context;
}

/* Returns a servername's userdata if any */
void *v_ssl_socket_context_find_server_name_userdata(struct v_ssl_socket_context *context, const char *hostname_pattern) {
    /* We can use sni_find because looking up a "wildcard pattern" will match the exact literal "wildcard pattern" first,
     * before it matches by the very wildcard itself, so it works fine (exact match is the only thing we care for here) */
    SSL_CTX *ssl_context = sni_find(context->sni, hostname_pattern);

    if (ssl_context)return SSL_CTX_get_ex_data(ssl_context, 0);

    return 0;
}

/* Returns either nullptr or the previously set user data attached to this SSL's selected SNI context */
void *v_ssl_socket_get_sni_userdata(struct v_ssl_socket *s) {
    return SSL_CTX_get_ex_data(SSL_get_SSL_CTX(s->ssl), 0);
}

/* TODO: return error on failure? */
void v_ssl_socket_context_add_server_name(struct v_ssl_socket_context *context, const char *hostname_pattern,
                                          struct v_socket_context_options options, void *user) {

    /* Try and construct an SSL_CTX from options */
    SSL_CTX *ssl_context = create_ssl_context_from_options(options);

    /* Attach the user data to this context */
    if (ssl_context) {
        if (1 != SSL_CTX_set_ex_data(ssl_context, 0, user)) {
            printf("CANNOT SET EX DATA!\n");
        }

        /* We do not want to hold any nullptr's in our SNI tree */
        /* If we already had that name, ignore */
        if (sni_add(context->sni, hostname_pattern, ssl_context))free_ssl_context(ssl_context);
    }
}

void v_ssl_socket_context_on_server_name(struct v_ssl_socket_context *context,
                                         void (*cb)(struct v_ssl_socket_context *, const char *hostname)) {
    context->on_server_name = cb;
}

void v_ssl_socket_context_remove_server_name(struct v_ssl_socket_context *context, const char *hostname_pattern) {
    /* The same thing must happen for sni_free, that's why we have a callback */
    SSL_CTX *sni_node_ssl_context = (SSL_CTX *) sni_remove(context->sni, hostname_pattern);
    free_ssl_context(sni_node_ssl_context);
}

/* Returns NULL or SSL_CTX. May call missing server name callback */
SSL_CTX *resolve_context(struct v_ssl_socket_context *context, const char *hostname) {
    /* Try once first */
    void *user = sni_find(context->sni, hostname);
    if (!user) {
        /* Emit missing hostname then try again
         * We have no callback registered, so fail
         */
        if (!context->on_server_name)return NULL;

        context->on_server_name(context, hostname);

        /* Last try */
        user = sni_find(context->sni, hostname);
    }
    return user;
}

/* Arg is context */
int sni_cb(SSL *ssl, int *al, void *arg) {
    if (ssl) {
        const char *hostname = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);
        if (hostname && hostname[0]) {
            /* Try and resolve (match) required hostname with what we have registered */
            SSL_CTX *resolved_ssl_context = resolve_context((struct v_ssl_socket_context *) arg, hostname);
            if (resolved_ssl_context) {
                SSL_set_SSL_CTX(ssl, resolved_ssl_context);
            } else { /* Call a blocking callback notifying of missing context */ }
        }
        return SSL_TLSEXT_ERR_OK;
    }
    /* Can we even come here ever? */
    return SSL_TLSEXT_ERR_NOACK;
}

struct v_ssl_socket_context *
v_create_ssl_socket_context(struct v_loop *loop, int context_ext_size, struct v_socket_context_options options) {
    /* If we haven't initialized the loop data yet, do so .
     * This is needed because loop data holds shared OpenSSL data and
     * the function is also responsible for initializing OpenSSL
     */
    v_internal_init_loop_ssl_data(loop);

    /* First of all we try and create the SSL context from options */
    SSL_CTX *ssl_context = create_ssl_context_from_options(options);
    /* We simply fail early if we cannot even create the OpenSSL context */
    if (!ssl_context) return NULL;

    /* Otherwise ee continue by creating a non-SSL context, but with larger ext to hold our SSL stuff */
    struct v_ssl_socket_context *context = (struct v_ssl_socket_context *)
            v_create_socket_context(0, loop, sizeof(struct v_ssl_socket_context) + context_ext_size, options);

    /* I guess this is the only optional callback */
    context->on_server_name = NULL;

    /* Then we extend its SSL parts */
    context->ssl_context = ssl_context;
    context->is_parent = 1;

    /* We, as parent context, may ignore data */
    context->sc.is_low_prio = (int (*)(struct v_socket *)) ssl_is_low_prio;

    /* Parent contexts may use SNI */
    SSL_CTX_set_tlsext_servername_callback(context->ssl_context, sni_cb);
    SSL_CTX_set_tlsext_servername_arg(context->ssl_context, context);

    /* Also create the SNI tree */
    context->sni = sni_new();

    return context;
}

/* Our destructor for hostnames, used below */
void sni_hostname_destructor(void *user) {
    /* Some nodes hold null, so this one must ignore this case */
    free_ssl_context((SSL_CTX *) user);
}

void v_ssl_socket_context_free(struct v_ssl_socket_context *context) {
    /* If we are parent then we need to free our OpenSSL context */
    if (context->is_parent) {
        free_ssl_context(context->ssl_context);

        /* Here we need to register a temporary callback for all still-existing hostnames
         * and their contexts. Only parents have an SNI tree */
        sni_free(context->sni, sni_hostname_destructor);
    }

    v_socket_context_free(0, &context->sc);
}

struct v_listen_socket *v_ssl_socket_context_listen(struct v_ssl_socket_context *context, const char *host,
                                                    int port, int options, int socket_ext_size) {
    return v_socket_context_listen(0, &context->sc, host, port, options,
                                   sizeof(struct v_ssl_socket) - sizeof(struct v_socket) + socket_ext_size);
}

struct v_listen_socket *v_ssl_socket_context_listen_unix(struct v_ssl_socket_context *context, const char *path,
                                                         int options, int socket_ext_size) {
    return v_socket_context_listen_unix(0, &context->sc, path, options,
                                        sizeof(struct v_ssl_socket) - sizeof(struct v_socket) + socket_ext_size);
}

struct v_ssl_socket *v_ssl_adopt_accepted_socket(struct v_ssl_socket_context *context, VENOK_SOCKET_DESCRIPTOR accepted_fd,
                                                 unsigned int socket_ext_size, char *addr_ip, int addr_ip_length) {
    return (struct v_ssl_socket *) v_adopt_accepted_socket(0, &context->sc, accepted_fd,
                                                           sizeof(struct v_ssl_socket) - sizeof(struct v_socket) + socket_ext_size,
                                                           addr_ip, addr_ip_length);
}

struct v_ssl_socket *v_ssl_socket_context_connect(struct v_ssl_socket_context *context, const char *host,
                                                  int port, const char *source_host, int options, int socket_ext_size) {
    return (struct v_ssl_socket *) v_socket_context_connect(0, &context->sc, host, port, source_host, options,
                                                            sizeof(struct v_ssl_socket) - sizeof(struct v_socket) + socket_ext_size);
}

struct v_ssl_socket *v_ssl_socket_context_connect_unix(struct v_ssl_socket_context *context, const char *server_path,
                                                       int options, int socket_ext_size) {
    return (struct v_ssl_socket *) v_socket_context_connect_unix(0, &context->sc, server_path, options,
                                                                 sizeof(struct v_ssl_socket) - sizeof(struct v_socket) + socket_ext_size);
}

void v_ssl_socket_context_on_open(struct v_ssl_socket_context *context,
                                  struct v_ssl_socket *(*on_open)(struct v_ssl_socket *s, int is_client, char *ip, int ip_length)) {
    v_socket_context_on_open(0, &context->sc, (struct v_socket *(*)(struct v_socket *, int, char *, int)) ssl_on_open);
    context->on_open = on_open;
}

void v_ssl_socket_context_on_close(struct v_ssl_socket_context *context,
                                   struct v_ssl_socket *(*on_close)(struct v_ssl_socket *s, int code, void *reason)) {
    v_socket_context_on_close(0, (struct v_socket_context *) context, (struct v_socket *(*)(struct v_socket *, int, void *)) ssl_on_close);
    context->on_close = on_close;
}

void v_ssl_socket_context_on_data(struct v_ssl_socket_context *context,
                                  struct v_ssl_socket *(*on_data)(struct v_ssl_socket *s, char *data, int length)) {
    v_socket_context_on_data(0, (struct v_socket_context *) context, (struct v_socket *(*)(struct v_socket *, char *, int)) ssl_on_data);
    context->on_data = on_data;
}

void v_ssl_socket_context_on_writable(struct v_ssl_socket_context *context, struct v_ssl_socket *(*on_writable)(struct v_ssl_socket *s)) {
    v_socket_context_on_writable(0, (struct v_socket_context *) context, (struct v_socket *(*)(struct v_socket *)) ssl_on_writable);
    context->on_writable = on_writable;
}

void v_ssl_socket_context_on_timeout(struct v_ssl_socket_context *context, struct v_ssl_socket *(*on_timeout)(struct v_ssl_socket *s)) {
    v_socket_context_on_timeout(0, (struct v_socket_context *) context, (struct v_socket *(*)(struct v_socket *)) on_timeout);
}

void v_ssl_socket_context_on_long_timeout(struct v_ssl_socket_context *context,
                                          struct v_ssl_socket *(*on_long_timeout)(struct v_ssl_socket *s)) {
    v_socket_context_on_long_timeout(0, (struct v_socket_context *) context, (struct v_socket *(*)(struct v_socket *)) on_long_timeout);
}

/* We do not really listen to passed FIN-handler, we entirely override it with
 * our handler since SSL doesn't really have support for half-closed sockets
 */
void v_ssl_socket_context_on_end(struct v_ssl_socket_context *context, struct v_ssl_socket *(*on_end)(struct v_ssl_socket *)) {
    v_socket_context_on_end(0, (struct v_socket_context *) context, (struct v_socket *(*)(struct v_socket *)) ssl_on_end);
}

void v_ssl_socket_context_on_connect_error(struct v_ssl_socket_context *context,
                                           struct v_ssl_socket *(*on_connect_error)(struct v_ssl_socket *, int code)) {
    v_socket_context_on_connect_error(0, (struct v_socket_context *) context,
                                      (struct v_socket *(*)(struct v_socket *, int)) on_connect_error);
}

void *v_ssl_socket_context_ext(struct v_ssl_socket_context *context) {
    return context + 1;
}

/* Per socket functions */
void *v_ssl_socket_get_native_handle(struct v_ssl_socket *s) {
    return s->ssl;
}

int v_internal_ssl_socket_write(struct v_ssl_socket *s, const char *data, int length, int msg_more) {
    if (v_socket_is_closed(0, &s->s) || v_ssl_socket_is_shutdown(s)) return 0;


    struct v_ssl_socket_context *context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);

    struct v_loop *loop = v_socket_context_loop(0, &context->sc);
    struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) loop->data.ssl_data;

    /* It makes literally no sense to touch this here! it should start at 0 and
     * ONLY be set and reset by the on_data function! the way is now,
     * triggering a write from a read will essentially delete all input data! what
     * we need to do is to check if this ever is non-zero and print a warning
     */
    loop_ssl_data->ssl_read_input_length = 0;

    loop_ssl_data->ssl_socket = &s->s;
    loop_ssl_data->msg_more = msg_more;
    loop_ssl_data->last_write_was_msg_more = 0;

    int written = SSL_write(s->ssl, data, length);
    loop_ssl_data->msg_more = 0;

    if (loop_ssl_data->last_write_was_msg_more && !msg_more) v_socket_flush(0, &s->s);

    if (written > 0) return written;
    else {
        int err = SSL_get_error(s->ssl, written);
        if (err == SSL_ERROR_WANT_READ) {
            /* Here we need to trigger writable event next ssl_read! */
            s->ssl_write_wants_read = 1;
        } else if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL) {
            /* These two errors may add to the error queue, which is per thread and must be cleared */

            /* All errors here except for want to write are critical and should not */
            ERR_clear_error();
        }

        return 0;
    }
}

struct v_ssl_socket *v_ssl_socket_context_adopt_socket(struct v_ssl_socket_context *context, struct v_ssl_socket *s, int ext_size) {
    /* TODO: this is completely untested */
    return (struct v_ssl_socket *) v_socket_context_adopt_socket(0, &context->sc, &s->s,
                                                                 sizeof(struct v_ssl_socket) - sizeof(struct v_socket) + ext_size);
}

void *v_ssl_socket_ext(struct v_ssl_socket *s) {
    return s + 1;
}

int v_ssl_socket_is_shutdown(struct v_ssl_socket *s) {
    return v_socket_is_shutdown(0, &s->s) || SSL_get_shutdown(s->ssl) & SSL_SENT_SHUTDOWN;
}

void v_ssl_socket_shutdown(struct v_ssl_socket *s) {
    if (!v_socket_is_closed(0, &s->s) && !v_ssl_socket_is_shutdown(s)) {
        struct v_ssl_socket_context *context = (struct v_ssl_socket_context *) v_socket_context(0, &s->s);
        struct v_loop *loop = v_socket_context_loop(0, &context->sc);
        struct loop_ssl_data *loop_ssl_data = (struct loop_ssl_data *) loop->data.ssl_data;

        /* Also makes no sense to touch this here! however the idea is that if THIS socket
         * is not the same as ssl_socket then this data is not for me but this is not correct
         * as it is currently anyway, any data available should be properly reset
         */
        loop_ssl_data->ssl_read_input_length = 0;


        /* Essentially we need two of these: one for CURRENT CALL and one for CURRENT SOCKET WITH DATA
         * if those match in the BIO function then you may read, if not then you may not read
         * we need ssl_read_socket to be set in on_data and checked in the BIO
         */
        loop_ssl_data->ssl_socket = &s->s;

        loop_ssl_data->msg_more = 0;

        /* Sets SSL_SENT_SHUTDOWN no matter what (not actually true if error!) */
        int ret = SSL_shutdown(s->ssl);
        if (ret == 0) ret = SSL_shutdown(s->ssl);

        if (ret < 0) {
            int err = SSL_get_error(s->ssl, ret);
            /* Clear */
            if (err == SSL_ERROR_SSL || err == SSL_ERROR_SYSCALL) ERR_clear_error();

            /* We get here if we are shutting down while still in init */
            v_socket_shutdown(0, &s->s);
        }
    }
}
#endif