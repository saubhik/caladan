extern "C" {
#include <base/log.h>
}

#include "runtime.h"
#include "net.h"

#include <string>
#include <memory>

void ServerHandler(void *arg) {
    std::unique_ptr<rt::TcpQueue> q(rt::TcpQueue::Listen(laddr, 4096));
    if (q == nullptr) panic("couldn't listen for connections");

    while (true) {
        rt:TcpConn *c = q->Accept();
        if (c == nullptr) panic("couldn't accept a connection");
    }
}

void ClientHandler(void *arg) {
    
}

int main(int argc, char *argv[]) {
    int ret;

    std::string cmd = argv[2];
    if (cmd.compare("server") == 0) {
        ret = runtime_init(argv[1], ServerHandler, NULL);
        if (ret) {
            printf("failed to start runtime\n");
            return ret;
        }
    }

    ret = runtime_init(argv[1], ClientHandler, NULL);
    if (ret) {
        printf("failed to start runtime\n");
        return ret;
    }

    return 0;
}