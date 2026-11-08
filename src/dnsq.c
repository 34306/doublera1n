/* dnsq <host>...: resolve each host with getaddrinfo, print its first address and the lookup time */
#include <stdio.h>
#include <netdb.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/time.h>
int main(int c, char **v) {
    for (int i = 1; i < c; i++) {
        struct addrinfo h = {0}, *r = NULL; h.ai_family = AF_UNSPEC; h.ai_socktype = SOCK_STREAM;
        struct timeval a, b; gettimeofday(&a, 0);
        int e = getaddrinfo(v[i], "80", &h, &r);
        gettimeofday(&b, 0);
        long ms = (b.tv_sec - a.tv_sec) * 1000 + (b.tv_usec - a.tv_usec) / 1000;
        if (e) { printf("%s: ERR %d %s (%ld ms)\n", v[i], e, gai_strerror(e), ms); continue; }
        char s[64];
        for (struct addrinfo *p = r; p; p = p->ai_next) {
            void *ad = p->ai_family == AF_INET ? (void *)&((struct sockaddr_in *)p->ai_addr)->sin_addr : (void *)&((struct sockaddr_in6 *)p->ai_addr)->sin6_addr;
            inet_ntop(p->ai_family, ad, s, sizeof s); printf("%s: %s (%ld ms)\n", v[i], s, ms); break;
        }
        freeaddrinfo(r);
    }
}
