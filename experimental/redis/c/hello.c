#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <hiredis.h>

/** Opening a Redis connection and running few basic commands. */

int main() {
    redisContext *c; // stores connection information
    redisReply *reply; 

    const char *hostname = "localhost";
    int port = 6379;

    struct timeval timeout = {1, 500000}; // 1.5 s
    c = redisConnectWithTimeout(hostname, port, timeout);

    // error handling: connection failed
    if (c == NULL || c->err) {
        if (c) { // if c->err nonzero, error.
            printf("Connection error: %s\n", c->errstr);
            redisFree(c);
        } else { // some other error
            printf("Connection error: can't allocate redis context\n");
        }
        exit(1);
    }

    // issue PING command - expect PONG
    reply = redisCommand(c, "PING");
    // reply->str gives response
    printf("PING: %s\n", reply->str);
    freeReplyObject(reply);

    // expect OK
    reply = redisCommand(c, "SET hello world");
    printf("SET hello world: %s\n", reply->str);
    freeReplyObject(reply);

    // expect "world"
    reply = redisCommand(c, "GET hello");
    printf("GET hello: %s\n", reply->str);
    freeReplyObject(reply);

    redisFree(c);
    return 0;
}
