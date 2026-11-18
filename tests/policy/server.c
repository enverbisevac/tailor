#include <netinet/in.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "--self-test") == 0) return 0;
    if (argc > 1 && strcmp(argv[1], "--fail") == 0) return 42;
    if (argc > 1 && strcmp(argv[1], "--hang") == 0) {
        for (;;) sleep(1);
    }
    int server = socket(AF_INET, SOCK_STREAM, 0);
    if (server < 0) return 1;
    int reuse = 1;
    setsockopt(server, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons(8080);
    address.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(server, (struct sockaddr *)&address, sizeof(address)) < 0 || listen(server, 8) < 0) return 2;
    for (;;) {
        int client = accept(server, 0, 0);
        if (client < 0) continue;
        char request[2048] = {0};
        ssize_t count = read(client, request, sizeof(request) - 1);
        const char *response = "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n";
        if (count > 0 && strncmp(request, "GET /health ", 12) == 0)
            response = "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";
        write(client, response, strlen(response));
        close(client);
    }
}
