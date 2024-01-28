#ifndef NETWORK_V_SOCKET_H
#define NETWORK_V_SOCKET_H

#ifdef _WIN32
#ifndef NOMINMAX
#define NOMINMAX
#endif
#define WIN32_LEAN_AND_MEAN
#endif

#ifdef __cplusplus
extern "C" {
#endif

#include "../src/socket/loop.h"
#include "../src/socket/poll.h"
#include "../src/socket/timer.h"

#include "../src/socket/tcp.h"
#include "../src/socket/udp.h"

#include "../src/socket/quic.h"

#ifdef __cplusplus
}
#endif

#endif //NETWORK_V_SOCKET_H
