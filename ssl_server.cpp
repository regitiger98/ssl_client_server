#include <stdio.h> // for perror
#include <stdlib.h> // atoi
#include <string.h> // for memset
#include <unistd.h> // for close
#include <arpa/inet.h> // for htons
#include <netinet/in.h> // for sockaddr_in
#include <sys/socket.h> // for socket

#include <set> // for set
#include <vector> // for vector
#include <thread> // for thread
#include <mutex> // for mutex
using namespace std;

set<int> Clients;
int bflag = 0;
mutex m;

void Chat(int childfd)
{
	while (true) {
		const static int BUFSIZE = 1024;
		char buf[BUFSIZE];
		char head[20];
		snprintf(head, 20, "Msg from %d : ", childfd);

		ssize_t received = recv(childfd, buf, BUFSIZE - 1, 0);
		if (received == 0 || received == -1) {
			perror("recv failed");
			m.lock();
			Clients.erase(childfd);
			m.unlock();
			break;

		}
		printf("Msg from %d : ", childfd);
		buf[received] = '\0';
		printf("%s\n", buf);
		
		if(bflag)
		{
			m.lock();
			for(auto i = Clients.begin(); i != Clients.end(); i++)
			{
				send(*i, head, strlen(head), 0);
				ssize_t sent = send(*i, buf, strlen(buf), 0);
				if (sent == 0) {
					perror("send failed");
					Clients.erase(*i);
				}
			}
			m.unlock();
		}
		else
		{
			send(childfd, head, strlen(head), 0);
			ssize_t sent = send(childfd, buf, strlen(buf), 0);
			if (sent == 0) {
				perror("send failed");
				m.lock();
				Clients.erase(childfd);
				m.unlock();
				break;
			}
		}
	}
}

int main(int argc, char *argv[]) {
	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
	if (sockfd == -1) {
		perror("socket failed");
		return -1;
	}

	int optval = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR,  &optval , sizeof(int));

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(argv[1]));
	addr.sin_addr.s_addr = htonl(INADDR_ANY);
	memset(addr.sin_zero, 0, sizeof(addr.sin_zero));

	int option;
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
		int childfd = accept(sockfd, reinterpret_cast<struct sockaddr*>(&addr), &clientlen);
		if (childfd < 0) {
			perror("ERROR on accept");
			break;
		}
		printf("connected %d\n", childfd);

		m.lock();
		Clients.insert(childfd);
		m.unlock();

		T.push_back(thread(Chat, childfd));
	}
	
	close(sockfd);
}
