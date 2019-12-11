#include <stdio.h> // for perror
#include <stdlib.h> // atoi
#include <string.h> // for memset
#include <unistd.h> // for close
#include <arpa/inet.h> // for htons
#include <netinet/in.h> // for sockaddr_in
#include <sys/socket.h> // for socket

#include <list> // for list
#include <vector> // for vector
#include <thread> // for thread
#include <mutex> // for mutex

#include "openssl/ssl.h"
#include "openssl/err.h"
using namespace std;

list<SSL*> Clients;
int bflag = 0;
mutex m;

int isRoot()
{
	if (getuid() != 0)
	{
		return 0;
	}
	else
	{
		return 1;
	}
}

SSL_CTX* InitServerCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
	SSL_load_error_strings();   /* load all error messages */
	method = (SSL_METHOD*)TLSv1_2_server_method();  /* create new server-method instance */
    	ctx = SSL_CTX_new(method);   /* create new context from method */
   	if ( ctx == NULL )
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}
    	return ctx;
}

void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    	/* set the local certificate from CertFile */
    	if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}
    	/* set the private key from KeyFile (may be the same as CertFile) */
    	if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    	{
        	ERR_print_errors_fp(stderr);
        	abort();
    	}
    	/* verify private key */
    	if ( !SSL_CTX_check_private_key(ctx) )
    	{
        	fprintf(stderr, "Private key does not match the public certificate\n");
        	abort();
    	}
}

void ShowCerts(SSL* ssl)
{
	X509 *cert;
	char *line;
	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
	if ( cert != NULL )
	{
		printf("Server certificates:\n");
		line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
		printf("Subject: %s\n", line);
		free(line);
		line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
		printf("Issuer: %s\n", line);
		free(line);
		X509_free(cert);
	}
	else
		printf("No certificates.\n");
}

void Chat(SSL *ssl, int childfd)
{
	const static int BUFSIZE = 1024;
	char buf[BUFSIZE], buf2[BUFSIZE + 20];
	char head[20];
	snprintf(head, 20, "Msg from %d : ", childfd);

	if(SSL_accept(ssl) == -1) {
		ERR_print_errors_fp(stderr);
		m.lock();
		Clients.remove(ssl);
		m.unlock();
	}
	else {
		printf("# of Clients : %lu\n", Clients.size());
		ShowCerts(ssl);
		while (true) {
			ssize_t received = SSL_read(ssl, buf, BUFSIZE - 1);
			if (received == 0 || received == -1) {
				perror("SSL_read failed");
				m.lock();
				Clients.remove(ssl);
				m.unlock();
				break;
			}
			buf[received] = '\0';
			snprintf(buf2, BUFSIZE, "%s%s", head, buf);
			printf("%s\n", buf2);

			if(bflag)
			{
				m.lock();
				for(auto i = Clients.begin(); i != Clients.end(); i++)
				{
					if(*i == ssl) continue;
					ssize_t sent = SSL_write(*i, buf2, strlen(buf2));
					if (sent == 0) {
						perror("SSL_write failed");
						Clients.erase(i);
						i--;
					}
				}
				m.unlock();
			}

			ssize_t sent = SSL_write(ssl, buf2, strlen(buf2));
			if (sent == 0) {
				perror("SSL_write failed");
				m.lock();
				Clients.remove(ssl);
				m.unlock();
				break;
			}
		}
		printf("# of Clients : %lu\n", Clients.size());
	}
	
	int sd = SSL_get_fd(ssl);       /* get socket connection */
	SSL_free(ssl);         /* release SSL state */
	close(sd);          /* close connection */
}

int main(int argc, char *argv[]) 
{
	if(!isRoot())
	{
		printf("This program must be run as root/sudo user!!");
		exit(0);
	}

	int portno = atoi(argv[1]), option;
	while((option = getopt(argc, argv, "b"))!=EOF) {
	        switch(option) {
	        	case 'b':
				bflag = 1;
				break;
			case '?':
				printf("Unknown option\n");
				exit(1);
	        }
	}

	SSL_library_init();
	SSL_CTX *ctx = InitServerCTX();		/* initialize SSL */
	LoadCertificates(ctx, "test.com.pem", "test.com.pem"); /* load certs */

	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,  &optval , sizeof(int));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(portno);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = bind(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("bind failed");
		return -1;
	}
	
	res = listen(sockfd, 2);
	if (res == -1) {
		perror("listen failed");
		return -1;
	}

	vector<thread> T;
	for(int i = 0;; i++) {
		struct sockaddr_in addr;
		socklen_t clientlen = sizeof(sockaddr);
		SSL *ssl;
		int childfd = accept(sockfd, reinterpret_cast<struct sockaddr*>(&addr), &clientlen);
		if (childfd < 0) {
			perror("ERROR on accept");
			break;
		}
		printf("connected %d\n", childfd);
		ssl = SSL_new(ctx);
		SSL_set_fd(ssl, childfd);

		m.lock();
		Clients.push_back(ssl);
		m.unlock();

		T.push_back(thread(Chat, ssl, childfd));
	}
	
	close(sockfd);
	SSL_CTX_free(ctx);
}
