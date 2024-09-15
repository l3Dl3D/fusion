#define THREADED
#include "../common/common.c"

// Taken some code from gnu tls documentation, 
// This example is a very simple echo server which supports X.509
// authentication, using the RSA ciphersuites. 
// This file has the leading comment of... /* This example code is
// placed in the public domain. */
// so there :>

#include <gcrypt.h>
#include <gnutls/gnutls.h>

#include <libHX/init.h>
#include <libHX/defs.h>
#include <libHX/map.h>
#include <libHX/string.h>

#define KEYFILE "/opt/fusion/ssl/key.pem"
#define CERTFILE "/opt/fusion/ssl/cert.pem"
#define CAFILE "/opt/fusion/ssl/ca.pem"
#define CRLFILE "/opt/fusion/ssl/crl.pem"

gnutls_certificate_credentials_t x509_cred;
gnutls_priority_t priority_cache;

static gnutls_session_t
initialize_tls_session (void)
{
	gnutls_session_t session;

	gnutls_init (&session, GNUTLS_SERVER);

	gnutls_priority_set (session, priority_cache);

	gnutls_credentials_set (session, GNUTLS_CRD_CERTIFICATE, x509_cred);

	/* 
	 *request client certificate if any.
	 */
	gnutls_certificate_server_set_request (session, GNUTLS_CERT_REQUEST);

	return session;
}


struct HXmap *dict;

struct data {
	void *data;
	size_t length;
};

struct data *gather_data(gnutls_session_t session, char *key, size_t length)
{
	unsigned char buffer[length];
	int offset, ret;
	struct data *data;

	for(offset = 0; offset < length; ) {
		ret = gnutls_record_recv(session, buffer + offset, (length - 
			offset) > 65535 ? 65535 : (length - offset));
		if(ret <= 0) return NULL;
		offset += ret;
	}

	data = malloc(sizeof(struct data));
	if(! data) return NULL;
	data->data = HX_memdup(buffer, length);
	if(!data->data) {
		free(data);
		return NULL;
	}
	data->length = length;

	//printf("gather data: returning %08x, data->length = %d\n", data, 
	// data->length);
	//fflush(stdout);

	return data;
}

#define NOKEY "// No key was specified\n"
#define NOTFOUND "// Key was not found\n"
#define KEYFOUND "// Key exists\n"
#define NOMEM "// Not enough memory to allocate\n"
#define UPDATEOK "// Updated successfully\n"

int update_data(gnutls_session_t session, char *key, size_t length)
{
	struct data *data;
	size_t offset;
	int ret;

	data = HXmap_get(dict, key);
	if(! data) {
		gnutls_record_send(session, NOTFOUND, strlen(NOTFOUND));
		return -1;
	}

	if(length > data->length) {
		void *tmp;
		tmp = realloc(data->data, length);
		if(! tmp) {
			gnutls_record_send(session, NOMEM, strlen(NOMEM));
			return -1;
		}
		data->data = tmp;
	}	

	for(offset = 0; offset < length; ) {
		ret = gnutls_record_recv(session, data->data + offset, 
			(length - offset) > 65535 ? 65535 : (length - offset));
		if(ret <= 0) return 0;
		offset += ret;
	}

	gnutls_record_send(session, UPDATEOK, strlen(UPDATEOK));

	data->length = length;
	return 0;
}

int send_data(gnutls_session_t session, char *key, struct data *data)
{
	int offset, ret;
	int to_send;

	char *msg;

	asprintf(&msg, "// Sending %d bytes\n", data->length);
	gnutls_record_send(session, msg, strlen(msg));
	free(msg);

	for(offset = 0; offset < data->length; ) {
		int tosend;
		tosend = (data->length - offset) > 65535 ? 65535 : 
			(data->length - offset);
		ret = gnutls_record_send(session, data->data + offset,
			 tosend);
		if(ret <= 0) return -1;
		offset += ret;
	}
	return 0;
}

void *free_data(void *ptr)
{
	struct data *data;
	data = (struct data *)(ptr);

	//printf("in free data, got %08x\n", (unsigned int)data);
	if(data) {
		if(data->data) {
			free(data->data);
		}
		free(data);
	}
}

void new_dict()
{
	struct HXmap_ops mops;
	if(dict) HXmap_free(dict);
	
	memset(&mops, 0, sizeof(mops));
	mops.d_free = free_data;
	
	dict = HXmap_init5(HXMAPT_HASH, HXMAP_SKEY | HXMAP_CKEY, &mops, 
		0, sizeof(struct data));
}


void *keyval_thread(void *arg)
{
	int fd = (int)arg;
	int ret;
	struct data *data;
	int cont;

	gnutls_session_t session;
	session = initialize_tls_session ();

	gnutls_transport_set_ptr (session, (gnutls_transport_ptr_t) fd);
	ret = gnutls_handshake (session);

	if (ret < 0) {
		char *msg;

		close (fd);
		gnutls_deinit (session);
	
		msg = NULL;
		asprintf(&msg, "*** Handshake has failed (%s)\n\n", 
			gnutls_strerror(ret));
		write(fd, msg, strlen(msg));
		close(fd);
		free(msg);
        }

#define BANNER "// Welcome to KeyValDaemon. Type 'h' for help information\n"
	gnutls_record_send(session, BANNER, strlen(BANNER));

	cont = 1;
	while(cont) {
		char cmdbuf[512], *p;
		char *args[6], *msg;
		int argcnt, i;

		memset(cmdbuf, 0, sizeof(cmdbuf));
		ret = gnutls_record_recv(session, cmdbuf, sizeof(cmdbuf));
		if(ret <= 0) break;

		p = strchr(cmdbuf, '\r');
		if(p) *p = 0;
		p = strchr(cmdbuf, '\n');
		if(p) *p = 0;

		memset(args, 0, sizeof(args));
		argcnt = HX_split5(cmdbuf, " ", 6, args);

#if 0
		for(i = 0; i < argcnt; i++) {
			asprintf(&msg, "args[%d] = \"%s\"\n", i, args[i]);
			gnutls_record_send(session, msg, strlen(msg));
			free(msg);
		}
#endif



		switch(args[0][0]) {
			case 'h': 
#define HELP \
"// f <key> - find entry and see if it exists\n" \
"// s <key> <bytes> - store an entry with key and <bytes> lenght of data\n" \
"// g <key> - read data from key\n" \
"// d <key> - delete key/data\n" \
"// X - delete all data and restart\n" 
// XXX, loop over HXmap and display data? 
	
				gnutls_record_send(session, HELP, strlen(HELP));
				break;
			case 'd':
				if(! args[1]) {
					gnutls_record_send(session, NOKEY, strlen(NOKEY));
				} else {
					void *data;

					data = HXmap_del(dict, args[1]);
					if(data) {
						gnutls_record_send(session, KEYFOUND, 
							strlen(KEYFOUND));
					} else {
						gnutls_record_send(session, NOTFOUND,
							strlen(NOTFOUND));
					}
				}
				break;
			case 's': // set
				data = gather_data(session, args[1], atoi(args[2]));
				if(data != NULL) {
#define NEWKEY "// New key added!\n"
					printf("args[1] = %08x/%s, data = %08x\n", 
						args[1], args[1], data);
					HXmap_add(dict, args[1], data);
					gnutls_record_send(session, NEWKEY, 
						strlen(NEWKEY));
				} else {
#define ADDERROR "// Unable to add new entry, problem getting data\n"
					gnutls_record_send(session, ADDERROR, 
						strlen(ADDERROR));
				}
				break;
			case 'u': // update
				update_data(session, args[1], atoi(args[2]));
				break;
			case 'f': // find
				if(! args[1]) {
					gnutls_record_send(session, NOKEY, 
						strlen(NOKEY));
				} else {
					if(HXmap_find(dict, args[1]) == NULL) {
						gnutls_record_send(session, 
						NOTFOUND, strlen(NOTFOUND));
					} else {
						gnutls_record_send(session,
						KEYFOUND, strlen(KEYFOUND));
					}
				}

				break;

			case 'g': // get
				if(! args[1]) {
					gnutls_record_send(session, NOKEY, 
						strlen(NOKEY));
				} else {
					if((data = HXmap_get(dict, args[1])) 
						== NULL) {
						gnutls_record_send(session, NOTFOUND,
						strlen(NOTFOUND));
					} else {
						send_data(session, args[1], data);
					}
				}
				break;
			case 'e':
				cont = 0;
				break;
			case 'X':
				new_dict();
#define NEWDICT "// New dictionary installed\n"
				gnutls_record_send(session, NEWDICT,
				strlen(NEWDICT));
				break;
			default:
#define UC "// Unknown Command, please see 'h' for help information\n"

				gnutls_record_send(session, UC, strlen(UC));
				break;
		}
	}


#define GB "// Good bye!\n"
	gnutls_record_send(session, GB, strlen(GB));
	gnutls_bye(session, GNUTLS_SHUT_WR);

	close(fd);
	gnutls_deinit(session);

	return NULL;
}

#define DH_BITS 512

static gnutls_dh_params_t dh_params;

static int generate_dh_params (void)
{
	/* 
	 * Generate Diffie-Hellman parameters - for use with DHE
	 * kx algorithms. When short bit length is used, it might
	 * be wise to regenerate parameters.
	 *
	 */
	gnutls_dh_params_init (&dh_params);
	gnutls_dh_params_generate2 (dh_params, DH_BITS);

	return 0;
}

GCRY_THREAD_OPTION_PTHREAD_IMPL;

int main(int argc, char **argv)
{
	int fd, i;

	HX_init();

	gcry_control(GCRYCTL_SET_THREAD_CBS, &gcry_threads_pthread);
	gnutls_global_init();

	gnutls_certificate_allocate_credentials (&x509_cred);
	gnutls_certificate_set_x509_trust_file (x509_cred, CAFILE,
						GNUTLS_X509_FMT_PEM);

	gnutls_certificate_set_x509_crl_file (x509_cred, CRLFILE,
						GNUTLS_X509_FMT_PEM);

	gnutls_certificate_set_x509_key_file (x509_cred, CERTFILE, KEYFILE,
					GNUTLS_X509_FMT_PEM);

	generate_dh_params ();

	gnutls_priority_init (&priority_cache, "NORMAL", NULL);
	gnutls_certificate_set_dh_params (x509_cred, dh_params);

	new_dict();

	signal(SIGPIPE, SIG_IGN);

	background_process(NAME, UID, GID);	
	serve_forever_threaded(PORT, keyval_thread);
}

