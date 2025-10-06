#include "peer-time-sync.h"

sockaddr_in my_address;
sockaddr_in peer_address; // used if we use -r and -a flags
Flags my_flags; // which parameters out of -b, -p, -a, -r were used
std::vector<sockaddr_in> connections;  // all of the connected peers
std::set<Peer> connections_set; // used to easily find wheter we are connected with sb
MyConnection synchronized_peer; // a node we are synchronized with
uint8_t synchronized = 255; // our synchronisation level
std::set<Peer> sent_connects; // used to check whether we are waiting for the ACK_CONNECT from sb
struct timespec start_time; // start of the program
int64_t offset = 0;
TimeSynchronised my_time; // t_1, t_2, t_3, t_4
uint64_t now;  // current time
uint64_t last_time = 0; // last time we sent SYNC_START
uint64_t last_sent_sync = 0; // last time we got SYNC_START from out synchronized peer
bool process = false;  // are we in the process of synchronisation?
uint64_t start_leader = 0; // when did we become the leader? used for those 2 sec after that
bool is_leader = false;
MyConnection candidate; // cadidate to become our synchronised peer
bool got_leader = false; // have i just become leader? used for those 2 sec after that
int socket_fd;

// Every message that has an error or is ignored should be printed.
void write_error_msg(std::array<uint8_t, UDP_MAX> message, size_t length) {
    std::cerr << "ERROR MSG ";

    size_t count = (length < 10) ? length : 10;
    for (size_t i = 0; i < count; ++i) {
        std::cerr << std::hex << std::setw(2) << std::setfill('0')
                  << (int)message[i];
    }

    std::cerr << std::dec << std::endl;
}

// Back to the start settings.
void restart() {
    offset = 0;
    TimeSynchronised temp;
    my_time = temp;
    MyConnection pom;
    synchronized_peer = pom;
    synchronized = 255;
}

// Checking if received message has right length.
bool check_right_length(std::array<uint8_t, UDP_MAX> buffer,
                        int received_length, int right_length) {
    if (received_length == right_length)
        return true;
    else {
        write_error_msg(buffer, received_length);
        return false;
    }
}

// Helper function to substract safely.
int64_t safe_diff(uint64_t a, uint64_t b) {
    if (a >= b)
        return static_cast<int64_t>(a - b);
    else
        return -static_cast<int64_t>(b - a);
}

int64_t calculate_offset(uint64_t t1, uint64_t t2, uint64_t t3, uint64_t t4) {
    int64_t delta1 = safe_diff(t2, t1);
    int64_t delta2 = safe_diff(t3, t4);
    return (delta1 + delta2) / 2;
}

// Used to assess whether two sockadrr_in are equal.
bool compare_sockaddr(const sockaddr_in& a, const sockaddr_in& b) {
    return (a.sin_family == b.sin_family &&
            a.sin_addr.s_addr == b.sin_addr.s_addr && a.sin_port == b.sin_port);
}

// Returns current time in milliseconds.
uint64_t get_curr_time_ms() {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t seconds = now.tv_sec - start_time.tv_sec;
    int64_t nanoseconds = now.tv_nsec - start_time.tv_nsec;

    if (nanoseconds < 0) {
        seconds -= 1;
        nanoseconds += 1000000000;
    }

    return seconds * 1000 + nanoseconds / 1000000;
}

// Function from labs to check given port.
uint16_t read_port(const std::string& port_str) {
    char* endptr;
    errno = 0;
    unsigned long port = std::strtoul(port_str.c_str(), &endptr, 10);
    if (errno != 0 || *endptr != '\0' || port == 0 || port > UINT16_MAX) {
        fatal("%s is not a valid port number", port_str.c_str());
    }
    return static_cast<uint16_t>(port);
}

// Checking if index is in the bound of argv.
bool check_exist(int argc, int i) {
    if (i < argc)
        return true;
    else
        fatal(
            "ERROR Zła postać podanych argumentów - po każdej fladze musisz "
            "podać wartość\n");
}

// Used to get an address from hostname - used for -a flag.
void get_ipv4_address(const std::string& input, sockaddr_in* sa) {
    if (sa == nullptr) {
        fatal("ERROR Wskaźnik na sockaddr_in nie może być nullptr.");
    }
    if (inet_pton(AF_INET, input.c_str(), &(sa->sin_addr)) == 1) {
        return;
    }

    addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;

    int status = getaddrinfo(input.c_str(), nullptr, &hints, &res);
    if (status != 0) {
        fatal("ERROR Nie można rozwiązać hosta");
    }

    char ipstr[INET_ADDRSTRLEN];
    sockaddr_in* ipv4 = (sockaddr_in*)res->ai_addr;
    inet_ntop(AF_INET, &(ipv4->sin_addr), ipstr, sizeof(ipstr));

    inet_pton(AF_INET, ipstr, &(sa->sin_addr));

    freeaddrinfo(res);
}

// Verifies flags the program runs with.
void verify_arguments(int argc, char* argv[]) {
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-b" && !my_flags.flag_b && check_exist(argc, ++i)) {
            if (inet_pton(AF_INET, argv[i], &my_address.sin_addr) != 1) {
                fatal("ERROR Nieprawidłowy adres IP dla -b: %s\n", argv[i]);
            }
            my_flags.flag_b = true;
        } else if (arg == "-p" && !my_flags.flag_p && check_exist(argc, ++i)) {
            if (strcmp(argv[i], "0") != 0)
                my_address.sin_port = htons(read_port(argv[i]));
            my_flags.flag_p = true;
        } else if (arg == "-a" && !my_flags.flag_a && check_exist(argc, ++i)) {
            get_ipv4_address(argv[i], &peer_address);
            my_flags.flag_a = true;
        } else if (arg == "-r" && !my_flags.flag_r && check_exist(argc, ++i)) {
            peer_address.sin_port = htons(read_port(argv[i]));
            my_flags.flag_r = true;
        } else {
            fatal(
                "ERROR Poprawne użycie programu zakłada używanie jedynie "
                "kazdej z flag -b, -p, -a, -r po jednym razie\n");
        }
    }
}

// Adds new peer to our connection list.
void add_connection(const sockaddr_in& peer_address) {
    connections.push_back(peer_address);
    Peer peer = {inet_ntoa(peer_address.sin_addr),
                 ntohs(peer_address.sin_port)};
    connections_set.insert(peer);
}

// Checks whether we have certain node in the connection list.
bool are_we_connected(sockaddr_in node) {
    Peer peer = {inet_ntoa(node.sin_addr), ntohs(node.sin_port)};
    return connections_set.find(peer) != connections_set.end();
}

// Generic function to send messages to a node.
void send_message(const sockaddr_in& peer_address, const uint8_t* message,
                  size_t mess_size, int socket_fd) {
    int send_flags = 0;
    socklen_t address_length = sizeof(peer_address);
    ssize_t sent_length = sendto(
        socket_fd, message, mess_size, send_flags,
        reinterpret_cast<const sockaddr*>(&peer_address), address_length);
    if (sent_length < 0) {
        syserr("sendto");
    } else if (static_cast<size_t>(sent_length) != mess_size) {
        std::cerr << "ERROR Incomplete message sent" << std::endl;
    }
}

// Preparing data to send SYNC_START message.
void sending_sync_start(uint64_t now) {
    uint8_t* start_sync = new uint8_t[10 * BYTE];
    start_sync[0] = MSG_SYNC_START;
    start_sync[1] = synchronized;
    uint64_t t1 = htobe64(now);
    std::memcpy(start_sync + 2 * BYTE, &t1, sizeof(t1));
    for (auto con : connections) {
        send_message(con, start_sync, 10 * BYTE, socket_fd);
    }
    delete[] start_sync;
}

// After receiving message HELLO.
void responding_hello(sockaddr_in client_address) {

    size_t length = 3 * BYTE;  // message + count
    for (auto conn : connections) {
        if (!compare_sockaddr(client_address, conn)) {
            length += sizeof(conn.sin_addr) + sizeof(conn.sin_port);
        }
    }
    if (length > UDP_MAX) {
        std::cerr << "ERROR Message size exceeds UDP_MAX. Length: " << length
                  << std::endl;
        return;
    }

    uint8_t* hello_reply = new uint8_t[length];
    size_t pos = 0;
    hello_reply[pos++] = MSG_HELLO_REPLY;

    // Couting how many peers I have without the one I got message from.
    uint16_t count_network = htons(connections.size() - 1);
    std::memcpy(hello_reply + pos, &count_network, sizeof(count_network));
    pos += sizeof(count_network);

    for (auto conn : connections) {
        if (!compare_sockaddr(client_address, conn)) {
            hello_reply[pos++] = sizeof(conn.sin_addr);
            std::memcpy(hello_reply + pos, &(conn.sin_addr),
                        sizeof(conn.sin_addr));
            pos += sizeof(conn.sin_addr);
            uint16_t port_network = conn.sin_port;
            std::memcpy(hello_reply + pos, &port_network, sizeof(port_network));
            pos += sizeof(port_network);
        }
    }

    send_message(client_address, hello_reply, pos, socket_fd);
    delete[] hello_reply;
}

// Responding to hello_reply by adding new peers to my list.
void responding_hello_reply(sockaddr_in client_address, ssize_t received_length,
                            std::array<uint8_t, UDP_MAX> buffer) {
    const uint8_t* ptr = buffer.data() + 1;
    uint16_t count_network;
    std::memcpy(&count_network, ptr, sizeof(count_network));
    ptr += sizeof(count_network);

    uint16_t counter = ntohs(count_network);

    add_connection(client_address);

    // Creating temporary list to make sure that the received list doesn't have
    // any mistakes.
    std::vector<std::pair<sockaddr_in, Peer>> temp_peers;

    for (int i = 0; i < counter; ++i) {
        if (ptr >= buffer.data() + received_length) {
            write_error_msg(buffer, received_length);
            return;
        }

        uint8_t peer_length = *ptr++;
        if (peer_length != 4) {
            write_error_msg(buffer, received_length);
            return;
        }

        in_addr addr{};
        if (peer_length == 4 * BYTE) {
            std::memcpy(&addr, ptr, peer_length);
        } else {
            write_error_msg(buffer, received_length);
        }
        ptr += peer_length;

        if (ptr + sizeof(uint16_t) > buffer.data() + received_length) {
            write_error_msg(buffer, received_length);
            return;
        }

        uint16_t port_network;
        std::memcpy(&port_network, ptr, sizeof(port_network));
        ptr += sizeof(port_network);

        uint16_t peer_port = ntohs(port_network);

        if (peer_port == 0) {
            write_error_msg(buffer, received_length);
            return;
        }

        if (addr.s_addr == INADDR_ANY || addr.s_addr == INADDR_NONE) {
            write_error_msg(buffer, received_length);
            return;
        }

        sockaddr_in temp{};
        temp.sin_family = AF_INET;
        temp.sin_addr = addr;
        temp.sin_port = htons(peer_port);
        if (compare_sockaddr(temp, my_address) ||
            compare_sockaddr(temp, client_address)) {
            write_error_msg(buffer, received_length);
            return;
        }
        Peer peer = {inet_ntoa(temp.sin_addr), ntohs(temp.sin_port)};
        temp_peers.emplace_back(temp, peer);

        if (temp_peers.size() > UDP_MAX)
            write_error_msg(buffer, received_length);
    }
    // Everything is OK - I can add to the right list.
    for (const auto& [sockaddr, peer] : temp_peers) {
        if (!are_we_connected(sockaddr)) {
            uint8_t connect_msg[1] = {MSG_CONNECT};
            send_message(sockaddr, connect_msg, sizeof(connect_msg), socket_fd);
            sent_connects.insert(peer);

            char ip_str[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &sockaddr.sin_addr, ip_str, sizeof(ip_str));
        }
    }
}

// After receiving SYNC_START, there are few conditions that need to be
// satisfied in order to start synchronising.
void responding_sync_start(sockaddr_in client_address,
                           std::array<uint8_t, UDP_MAX> buffer,
                           ssize_t received_length) {
    if (client_address.sin_addr.s_addr ==
            synchronized_peer.sockaddr.sin_addr.s_addr &&
        client_address.sin_port == synchronized_peer.sockaddr.sin_port &&
        my_time.is_synchronised) {
        if (buffer[1] < synchronized_peer.synchronised) {
            candidate = synchronized_peer;
            synchronized_peer.synchronised = buffer[1];
            process = true;
            last_sent_sync = get_curr_time_ms();
        } else if (buffer[1] >= synchronized) {
            restart();
            process = false;
        } else {
            last_sent_sync = get_curr_time_ms();
        }
    } else {
        if (buffer[1] <= synchronized - 2) {
            candidate.sockaddr = client_address;
            candidate.synchronised = buffer[1];
            process = true;
        } else {
            write_error_msg(buffer, received_length);
        }
    }
    if (process) {
        const uint8_t* ptr = buffer.data() + 2 * BYTE;
        std::memcpy(&my_time.t1, ptr, sizeof(my_time.t1));
        my_time.t1 = be64toh(my_time.t1);
        my_time.t2 = now;
        my_time.synchronised = buffer[1 * BYTE];
        uint8_t request[1 * BYTE];
        request[0] = MSG_DELAY_REQUEST;
        send_message(client_address, request, 1 * BYTE, socket_fd);
        my_time.t3 = get_curr_time_ms();
    }
}

// After receiving LEADER, we need to check whether our synchronized level
// should change.
void responding_leader(std::array<uint8_t, UDP_MAX> buffer, ssize_t received_length) {
    int check_leader = buffer[1 * BYTE];
    if (check_leader == 0 && synchronized != 0) {
        is_leader = true;
        got_leader = true;
        start_leader = get_curr_time_ms();
        restart();
        synchronized = 0;
        process = false;
    } else if (check_leader == 255 && synchronized == 0) {
        restart();
        is_leader = false;
        got_leader = false;
    } else if (synchronized != 0) {
        write_error_msg(buffer, received_length);
    }
}

// Responding to the DELAY REQUEST by sending DELAY RESPONSE.
void responding_delay_request(sockaddr_in client_address) {
    uint8_t* response = new uint8_t[10 * BYTE];
    response[0] = MSG_DELAY_RESPONSE;
    response[1] = synchronized;
    now = get_curr_time_ms();
    uint64_t t4 = htobe64(now - offset);
    std::memcpy(response + 2 * BYTE, &t4, sizeof(t4));

    send_message(client_address, response, 10 * BYTE, socket_fd);
    delete[] response;
}

// Responding to DELAY_RESPONSE by checking conditions and counting offset.
// We're synchronised since then.
void responding_delay_response(std::array<uint8_t, UDP_MAX> buffer,
                               ssize_t received_length) {
    const uint8_t* ptr = buffer.data() + 2 * BYTE;
    std::memcpy(&my_time.t4, ptr, sizeof(my_time.t4));
    my_time.t4 = be64toh(my_time.t4);
    now = get_curr_time_ms();
    if (my_time.t3 > now || now - my_time.t3 >= 10000 || my_time.t4 < my_time.t1) {
        write_error_msg(buffer, received_length);
    } else {
        if (my_time.synchronised == buffer[1]) {
            offset = calculate_offset(my_time.t1, my_time.t2, my_time.t3, my_time.t4);
            synchronized = buffer[1] + 1;
            synchronized_peer = candidate;
            my_time.is_synchronised = true;
            last_sent_sync = get_curr_time_ms();
        } else {
            write_error_msg(buffer, received_length);
        }
    }
    process = false;
}

// Responding to GET TIME by sending our time and level of synchronisation.
void responding_get_time(sockaddr_in client_address) {
    uint8_t time[10 * BYTE];
    time[0] = MSG_TIME;
    time[1] = synchronized;
    now = get_curr_time_ms();
    uint64_t t = htobe64(now - offset);
    std::memcpy(&time[2], &t, sizeof(t));
    send_message(client_address, time, 10 * BYTE, socket_fd);
}

// Main loop where we communicate with the nodes and receive messages.
void receiving(int socket_fd) {
    ssize_t received_length = 0;
    bool finished = false;

    struct timeval timeout;
    timeout.tv_sec = 1;

    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout,
                   sizeof(timeout)) < 0)
        syserr("setsockopt failed");

    do {
        now = get_curr_time_ms();
        if (now - last_sent_sync >= 20000 && my_time.is_synchronised)
            restart();
        if (now - my_time.t3 >= 10000 && process) {
            process = false;
            MyConnection can;
            candidate = can;
        }

        if (((got_leader && now - start_leader >= 2000) || (!got_leader && now - last_time >= 5000)) &&
            synchronized < 254 && connections.size() > 0) {
            sending_sync_start(now - offset);
            if (got_leader)
                got_leader = false;
            last_time = get_curr_time_ms();
        }

        std::array<uint8_t, UDP_MAX> buffer{};
        sockaddr_in client_address{};
        socklen_t address_length = sizeof(client_address);

        received_length = recvfrom(socket_fd, buffer.data(), buffer.size(), 0,
                                   reinterpret_cast<sockaddr*>(&client_address), &address_length);
        now = get_curr_time_ms();
        if (received_length < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK);
            else
                syserr("recvfrom");
        } else if (received_length > 0) {
            if (buffer[0] == MSG_HELLO) {
                if (check_right_length(buffer, received_length, 1 * BYTE)) {
                    if (!are_we_connected(client_address))
                        add_connection(client_address);
                    responding_hello(client_address);
                }
            } else if (buffer[0] == MSG_HELLO_REPLY && my_flags.flag_a && my_flags.flag_r) {
                if (client_address.sin_addr.s_addr == peer_address.sin_addr.s_addr &&
                    client_address.sin_port == peer_address.sin_port)
                    responding_hello_reply(client_address, received_length, buffer);
                else
                    write_error_msg(buffer, received_length);
            } else if (buffer[0] == MSG_CONNECT) {
                if (check_right_length(buffer, received_length, 1 * BYTE)) {
                    uint8_t connect_ack[1] = {MSG_ACK_CONNECT};
                    send_message(client_address, connect_ack, sizeof(connect_ack), socket_fd);
                    if (!are_we_connected(client_address))
                        add_connection(client_address);
                }
            } else if (buffer[0] == MSG_ACK_CONNECT) {
                if (check_right_length(buffer, received_length, 1 * BYTE)) {
                    Peer incoming_peer = {inet_ntoa(client_address.sin_addr),
                                          ntohs(client_address.sin_port)};
                    if (sent_connects.find(incoming_peer) != sent_connects.end()) {
                        sent_connects.erase(incoming_peer);
                        add_connection(client_address);
                    } else
                        write_error_msg(buffer, received_length);
                }
            } else if (buffer[0] == MSG_SYNC_START && (!process || compare_sockaddr(client_address,
                                         synchronized_peer.sockaddr)) && !is_leader) {
                if (are_we_connected(client_address)) {
                    if (process && compare_sockaddr(client_address, synchronized_peer.sockaddr) &&
                        my_time.is_synchronised)
                        last_sent_sync = get_curr_time_ms();
                    else if (!process)
                        if (check_right_length(buffer, received_length, 10 * BYTE))
                            responding_sync_start(client_address, buffer, received_length);
                } else
                    write_error_msg(buffer, received_length);
            } else if (buffer[0] == MSG_LEADER) {
                if (check_right_length(buffer, received_length, 2 * BYTE))
                    responding_leader(buffer, received_length);
            } else if (buffer[0] == MSG_DELAY_REQUEST) {
                if (are_we_connected(client_address)) {
                    if (check_right_length(buffer, received_length, 1 * BYTE))
                        responding_delay_request(client_address);
                } else
                    write_error_msg(buffer, received_length);
            } else if (buffer[0] == MSG_DELAY_RESPONSE && process) {
                if (are_we_connected(client_address) &&
                    compare_sockaddr(client_address, candidate.sockaddr)) {
                    if (check_right_length(buffer, received_length, 10 * BYTE))
                        responding_delay_response(buffer, received_length);
                } else
                    write_error_msg(buffer, received_length);
            } else if (buffer[0] == MSG_GET_TIME) {
                if (check_right_length(buffer, received_length, 1 * BYTE))
                    responding_get_time(client_address);
            } else
                    write_error_msg(buffer, received_length);
        }
    } while (!finished);
}

int main(int argc, char* argv[]) {
    clock_gettime(CLOCK_MONOTONIC, &start_time);

    my_address.sin_family = AF_INET;
    my_address.sin_addr.s_addr = htonl(INADDR_ANY);
    my_address.sin_port = htons(0);

    peer_address.sin_family = AF_INET;
    peer_address.sin_addr.s_addr = htonl(INADDR_ANY);
    peer_address.sin_port = htons(0);

    if (argc > 1) {
        verify_arguments(argc, argv);
        if ((my_flags.flag_r && !my_flags.flag_a) ||
            (my_flags.flag_a && !my_flags.flag_r))
            fatal("Flagi -a oraz -r muszą wystąpić razem");
    }

    socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        syserr("cannot create a socket");
    }
    if (bind(socket_fd, reinterpret_cast<sockaddr*>(&my_address),
             sizeof(my_address)) < 0) {
        syserr("bind");
    }
    socklen_t addr_len = sizeof(my_address);
    if (getsockname(socket_fd, reinterpret_cast<sockaddr*>(&my_address),
                    &addr_len) < 0) {
        syserr("getsockname");
    }

    if (my_flags.flag_a && my_flags.flag_r) {
        uint8_t hello[1] = {MSG_HELLO};
        send_message(peer_address, hello, sizeof(hello), socket_fd);
    }

    receiving(socket_fd);
    close(socket_fd);
    return 0;
}