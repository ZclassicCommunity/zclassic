/* zcl-port-stress: one worker of the zcl-port lease stress test (see
 * zcl-port-stress.sh, which runs many in parallel). Each round: lease a block of
 * <count> ports, actually bind and listen on every one (SO_REUSEADDR off), claim
 * a marker file <dir>.held/<port> with O_EXCL (a second claimant = duplicate
 * lease), then drop the claims, close the sockets and release the lease.
 * usage: zcl-port-stress <zcl-port> <leasedir> <rounds> <count>
 * prints "rounds=N dups=D bindfail=B leasefail=L"; exit 0 iff D=B=L=0. gnu17. */
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <direct.h>
#include <io.h>
#define POPEN _popen
#define PCLOSE _pclose
#define MKDIR(p) _mkdir(p)
#define CLOSESOCK closesocket
#define SELFPID() ((long)GetCurrentProcessId())
#else
#define _POSIX_C_SOURCE 200809L
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#define POPEN popen
#define PCLOSE pclose
#define MKDIR(p) mkdir((p), 0700)
#define CLOSESOCK close
#define SELFPID() ((long)getpid())
typedef int SOCKET;
#endif
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

int main(int argc, char **argv)
{
    long rounds, count, dups = 0, bindfail = 0, leasefail = 0, done = 0;
    char held[600], cmd[1200], line[64], path[700];
    if (argc != 5) { fprintf(stderr, "usage: zcl-port-stress <zcl-port> <leasedir> <rounds> <count>\n"); return 2; }
    rounds = atol(argv[3]); count = atol(argv[4]);
    if (count < 1 || count > 64) return 2;
#ifdef _WIN32
    { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); }
#endif
    snprintf(held, sizeof held, "%s.held", argv[2]);
    MKDIR(held);
    for (long r = 0; r < rounds; r++) {
        long ports[64]; SOCKET socks[64]; int mine[64]; long n = 0;
        FILE *p;
        snprintf(cmd, sizeof cmd, "\"%s\" lease %ld --block --dir \"%s\" --owner %ld", argv[1], count, argv[2], SELFPID());
        p = POPEN(cmd, "r");
        if (!p) { leasefail++; continue; }
        while (n < count && fgets(line, sizeof line, p)) ports[n++] = atol(line);
        if (PCLOSE(p) != 0 || n != count) { leasefail++; continue; }
        for (long i = 0; i < n; i++) {
            struct sockaddr_in sa;
            int fd;
            socks[i] = socket(AF_INET, SOCK_STREAM, 0);
            memset(&sa, 0, sizeof sa);
            sa.sin_family = AF_INET;
            sa.sin_addr.s_addr = htonl(0x7f000001UL);
            sa.sin_port = htons((unsigned short)ports[i]);
            if (bind(socks[i], (struct sockaddr *)&sa, (int)sizeof sa) != 0 || listen(socks[i], 1) != 0) bindfail++;
            snprintf(path, sizeof path, "%s/%ld", held, ports[i]);
            fd = open(path, O_CREAT | O_EXCL | O_WRONLY, 0644);
            mine[i] = fd >= 0; if (fd < 0) dups++; else close(fd);
        }
        for (long i = 0; i < n; i++) {
            CLOSESOCK(socks[i]);
            snprintf(path, sizeof path, "%s/%ld", held, ports[i]);
            if (mine[i]) remove(path);
        }
        snprintf(cmd, sizeof cmd, "\"%s\" release --dir \"%s\" --owner %ld", argv[1], argv[2], SELFPID());
        if (system(cmd) != 0) leasefail++;
        done++;
    }
    printf("rounds=%ld dups=%ld bindfail=%ld leasefail=%ld\n", done, dups, bindfail, leasefail);
    return dups || bindfail || leasefail ? 1 : 0;
}
