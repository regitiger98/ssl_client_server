#include <stdio.h> // for perror
#include <stdlib.h> // for atoi
#include <string.h> // for memset
#include <unistd.h> // for close
#include <arpa/inet.h> // for htons
#include <netinet/in.h> // for sockaddr_in
#include <sys/socket.h> // for socket

#include <thread>

#include <openssl/ssl.h>
#include <openssl/err.h>
using namespace std;

SSL_CTX* InitCTX(void)
{
	SSL_METHOD *method;
	SSL_CTX *ctx;
	OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
	SSL_load_error_strings();   /* Bring in and register error messages */
	method = (SSL_METHOD*)TLSv1_2_client_method();  /* Create new client-method instance */
	ctx = SSL_CTX_new(method);   /* Create new context */
	if ( ctx == NULL )
	{
		ERR_print_errors_fp(stderr);
		abort();
	}
	return ctx;
}

void Recv(SSL *ssl)
{
	const static int BUFSIZE = 1024;
	char buf[BUFSIZE];

	while (true) {
		ssize_t received = SSL_read(ssl, buf, BUFSIZE - 1);
		if (received == 0 || received == -1) {
			perror("SSL_read failed");
			exit(1);
		}
		buf[received] = '\0';
		printf("%s\n", buf);
	}
}

int main(int argc, char *argv[]) {
	if ( argc != 3 )
	{
		printf("usage: %s <hostname> <portnum>\n", argv[0]);
		exit(0);
	}
	

	SSL_library_init();
	SSL_CTX *ctx = InitCTX();
	
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[2]));
	addr.sin_addr.s_addr = inet_addr(argv[1]);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int res = connect(sockfd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(struct sockaddr));
	if (res == -1) {
		perror("connect failed");
		return -1;
	}
	printf("connected to %s:%s\n", argv[1], argv[2]);

	SSL *ssl = SSL_new(ctx);
	SSL_set_fd(ssl, sockfd);
	if(SSL_connect(ssl) == -1)
		ERR_print_errors_fp(stderr);
	else
	{
		thread Thread(Recv, ssl);
		while (true) {
			const static int BUFSIZE = 1024;
			char buf[BUFSIZE];

			scanf("%s", buf);
			if (strcmp(buf, "quit") == 0) {
				close(sockfd);
				exit(1);
			}

			ssize_t sent = SSL_write(ssl, buf, strlen(buf));
			if (sent == 0) {
				perror("SSL_write failed");
				exit(1);
			}
		}
		Thread.join();
	}

	close(sockfd);
	SSL_CTX_free(ctx);
}
