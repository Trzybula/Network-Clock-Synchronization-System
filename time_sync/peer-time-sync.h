
#ifndef CLIENT
#define CLIENT

#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <netdb.h>
#include <unistd.h>
#include <time.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>
#include <iomanip> 
#include <arpa/inet.h> // htonl, ntohl
#include "err.h"
#include <array>
#include <vector>
#include <set>
#include <cstdint>
#include <netinet/in.h>
#include <utility>

#define UDP_MAX 65535
#define BYTE 1

// Typy wiadomości
#define MSG_HELLO 1
#define MSG_HELLO_REPLY 2
#define MSG_CONNECT 3
#define MSG_ACK_CONNECT 4
#define MSG_SYNC_START 11
#define MSG_DELAY_REQUEST 12
#define MSG_DELAY_RESPONSE 13
#define MSG_LEADER 21
#define MSG_GET_TIME 31
#define MSG_TIME 32

using Peer = std::pair<std::string, uint16_t>;

struct MyConnection {
    sockaddr_in sockaddr{};
    uint8_t synchronised = 255;
};

struct TimeSynchronised {
    uint64_t t1 = 0;
    uint64_t t2 = 0;
    uint64_t t3 = 0;
    uint64_t t4 = 0;
    uint8_t synchronised = 0;
    bool is_synchronised = false;
};

struct Flags {
    bool flag_a = false;
    bool flag_r = false;
    bool flag_b = false;
    bool flag_p = false;
};

// Funkcje
void write_error_msg(std::array<uint8_t, UDP_MAX> message, size_t length);
int64_t safe_diff(uint64_t a, uint64_t b);
int64_t calculate_offset(uint64_t t1, uint64_t t2, uint64_t t3, uint64_t t4);
uint64_t get_curr_time_ms();
uint16_t read_port(const std::string& port_str);
bool check_exist(int argc, int i);
void verify_arguments(int argc, char* argv[]);
void add_connection(const sockaddr_in& peer_address);
bool are_we_connected(sockaddr_in node);
void send_message(const sockaddr_in& peer_address, const uint8_t* message, size_t mess_size, int socket_fd);
bool compare_sockaddr(const sockaddr_in& a, const sockaddr_in& b);
bool check_right_length(std::array<uint8_t, UDP_MAX> buffer, int received_length, int right_length);
void responding_hello(sockaddr_in client_address, std::array<uint8_t, UDP_MAX> buffer, ssize_t received_length);
void responding_hello_reply(sockaddr_in client_address, std::array<uint8_t, UDP_MAX> buffer, ssize_t received_length);
void responding_sync_start(sockaddr_in client_address, std::array<uint8_t, UDP_MAX> buffer, ssize_t received_length);
void responding_leader(std::array<uint8_t, UDP_MAX> buffer, ssize_t received_length);
void responding_delay_request(sockaddr_in client_address);
void responding_delay_response(std::array<uint8_t, UDP_MAX> buffer, ssize_t received_length);
void responding_get_time(sockaddr_in client_address);
void sending_sync_start(uint64_t now);
#endif
