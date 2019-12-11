all: ssl_client ssl_server

ssl_client: ssl_client.cpp
	g++ -o ssl_client ssl_client.cpp -pthread

ssl_server: ssl_server.cpp
	g++ -o ssl_server ssl_server.cpp -pthread

clean: 
	rm ssl_client ssl_server
