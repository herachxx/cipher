/**
 * CIPHER - network analysis utilities
 * cross-platform: Windows (Winsock2) + Linux/macOS (POSIX)
 * 
 * on WINDOWS (MinGW/g++):
 *  g++ -std=c++17 -O2 -Wall -o cipher_net cipher_net.cpp -lws2_32
 *
 * on Linux/macOS:
 *  g++ -std=c++17 -O2 -Wall -o cipher_net cipher_net.cpp
 *
 * usage:
 *  cipher_net ip <address>
 *  cipher_net cidr <address/prefix>
 *  cipher_net scan <host> <start_port> <end_port>
 *
 * WARNING: only scan hosts you own or have permission to test.
 */

// platform detection
#ifdef _WIN32
  #define WIN32_LEAN_AND_MEAN
  #ifndef NOMINMAX
    #define NOMINMAX
  #endif
  #include <winsock2.h>
  #include <ws2tcpip.h>
  #pragma comment(lib, "ws2_32.lib")
  #define CLOSE_SOCKET(s) closesocket(s)
  using socket_t = SOCKET;
  static const socket_t BAD_SOCKET = INVALID_SOCKET;
#else
  #include <arpa/inet.h>
  #include <fcntl.h>
  #include <netdb.h>
  #include <netinet/in.h>
  #include <sys/select.h>
  #include <sys/socket.h>
  #include <unistd.h>
  #define CLOSE_SOCKET(s) close(s)
  using socket_t = int;
  static const socket_t BAD_SOCKET = -1;
#endif

#include <algorithm>
#include <chrono>
#include <cstring>
#include <iostream>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

// ANSI colours
namespace Color {
#ifdef _WIN32
  inline void enable() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(h, &mode);
    SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
  }
#else
  inline void enable() {}
#endif
  constexpr const char* RESET = "\033[0m";
  constexpr const char* CYAN = "\033[96m";
  constexpr const char* GREEN = "\033[92m";
  constexpr const char* YELLOW = "\033[93m";
  constexpr const char* RED = "\033[91m";
  constexpr const char* DIM = "\033[2m";
  constexpr const char* BOLD = "\033[1m";
}

// winsock RAII guard
struct WinsockGuard {
  WinsockGuard() {
#ifdef _WIN32
    WSADATA wsa{};
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
      throw std::runtime_error("WSAStartup failed");
#endif
  }
  ~WinsockGuard() {
#ifdef _WIN32
    WSACleanup();
#endif
  }
};

// IPv4 address
struct IPv4Address {
  uint32_t value = 0;
  static IPv4Address parse(const std::string& s) {
    struct in_addr addr{};
    if (inet_pton(AF_INET, s.c_str(), &addr) != 1)
      throw std::invalid_argument("Invalid IPv4 address: " + s);
    IPv4Address ip;
    ip.value = ntohl(addr.s_addr);
    return ip;
  }
  std::string toString() const {
    struct in_addr addr{};
    addr.s_addr = htonl(value);
    char buf[INET_ADDRSTRLEN]{};
    inet_ntop(AF_INET, &addr, buf, sizeof(buf));
    return buf;
  }
  bool isLoopback()      const { return (value & 0xFF000000u) == 0x7F000000u; }
  bool isPrivate()       const {
    return isLoopback()
        || (value & 0xFF000000u) == 0x0A000000u
        || (value & 0xFFF00000u) == 0xAC100000u
        || (value & 0xFFFF0000u) == 0xC0A80000u;
  }
  bool isMulticast()     const { return (value & 0xF0000000u) == 0xE0000000u; }
  bool isBroadcast()     const { return value == 0xFFFFFFFFu; }
  bool isLinkLocal()     const { return (value & 0xFFFF0000u) == 0xA9FE0000u; }
  bool isDocumentation() const {
    return (value & 0xFFFFFF00u) == 0xC0000200u
        || (value & 0xFFFFFF00u) == 0xC6336400u
        || (value & 0xFFFFFF00u) == 0xCB007100u;
  }
  std::string classify() const {
    if (isLoopback())      return "Loopback";
    if (isBroadcast())     return "Broadcast";
    if (isMulticast())     return "Multicast";
    if (isLinkLocal())     return "Link-Local (APIPA)";
    if (isDocumentation()) return "Documentation / TEST-NET";
    if (isPrivate())       return "Private (RFC 1918)";
    return "Public / Routable";
  }
  std::string rfcClass() const {
    uint8_t first = (value >> 24) & 0xFF;
    if (first < 128) return "A";
    if (first < 192) return "B";
    if (first < 224) return "C";
    if (first < 240) return "D (Multicast)";
    return "E (Reserved)";
  }
  std::string toBinaryString() const {
    std::string s;
    s.reserve(35);
    for (int i = 31; i >= 0; --i) {
      s += ((value >> i) & 1) ? '1' : '0';
      if (i > 0 && i % 8 == 0) s += '.';
    }
    return s;
  }
};

// CIDR subnet
struct CIDRSubnet {
  IPv4Address network;
  int prefix = 0;
  static CIDRSubnet parse(const std::string& cidr) {
    auto slash = cidr.find('/');
    if (slash == std::string::npos)
      throw std::invalid_argument("Expected CIDR notation: a.b.c.d/prefix");
    CIDRSubnet s;
    s.network = IPv4Address::parse(cidr.substr(0, slash));
    s.prefix  = std::stoi(cidr.substr(slash + 1));
    if (s.prefix < 0 || s.prefix > 32)
      throw std::invalid_argument("Prefix length must be 0-32");
    s.network.value &= s.mask();
    return s;
  }
  uint32_t mask()         const { return prefix == 0 ? 0u : (~0u << (32 - prefix)); }
  uint32_t wildcardMask() const { return ~mask(); }
  IPv4Address broadcastAddr() const {
    IPv4Address a; a.value = network.value | wildcardMask(); return a;
  }
  IPv4Address firstHost() const {
    IPv4Address a;
    a.value = (prefix == 32) ? network.value : network.value + 1;
    return a;
  }
  IPv4Address lastHost() const {
    IPv4Address a;
    a.value = (prefix >= 31) ? broadcastAddr().value : broadcastAddr().value - 1;
    return a;
  }
  uint64_t totalHosts() const {
    if (prefix == 32) return 1;
    if (prefix == 31) return 2;
    return (1ULL << (32 - prefix)) - 2;
  }
  std::string maskString() const {
    IPv4Address m; m.value = mask(); return m.toString();
  }
};

// port scanner
static const std::vector<std::pair<uint16_t, const char*>> KNOWN_PORTS = {
  {21,    "ftp"},       {22,   "ssh"},       {23,   "telnet"},
  {25,    "smtp"},      {53,   "dns"},       {80,   "http"},
  {110,   "pop3"},      {143,  "imap"},      {443,  "https"},
  {445,   "smb"},       {3306, "mysql"},     {3389, "rdp"},
  {5432,  "postgres"},  {6379, "redis"},     {8080, "http-alt"},
  {8443,  "https-alt"}, {27017,"mongodb"},   {11211,"memcached"},
};
static std::string guessService(uint16_t port) {
  for (auto& [p, name] : KNOWN_PORTS)
    if (p == port) return name;
  return "unknown";
}
struct PortResult { uint16_t port; bool open; std::string service; };
PortResult probePort(const std::string& host, uint16_t port, int timeoutMs = 800) {
  PortResult result{ port, false, guessService(port) };
  struct addrinfo hints{}, *res = nullptr;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;
  if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
    return result;
  struct sockaddr_in addr{};
  addr.sin_family = AF_INET;
  addr.sin_port = htons(port);
  addr.sin_addr = reinterpret_cast<struct sockaddr_in*>(res->ai_addr)->sin_addr;
  freeaddrinfo(res);
  socket_t fd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (fd == BAD_SOCKET) return result;

  // setting non-blocking
#ifdef _WIN32
  u_long nb = 1;
  ioctlsocket(fd, FIONBIO, &nb);
#else
  int flags = fcntl(fd, F_GETFL, 0);
  fcntl(fd, F_SETFL, flags | O_NONBLOCK);
#endif
  connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr));
  fd_set wset;
  FD_ZERO(&wset);
  FD_SET(fd, &wset);
  struct timeval tv{ timeoutMs / 1000, (timeoutMs % 1000) * 1000 };
  if (select(static_cast<int>(fd) + 1, nullptr, &wset, nullptr, &tv) == 1) {
    int err = 0;
    socklen_t len = sizeof(err);
    getsockopt(fd, SOL_SOCKET, SO_ERROR,
               reinterpret_cast<char*>(&err), &len);
    result.open = (err == 0);
  }
  CLOSE_SOCKET(fd);
  return result;
}

// pretty print helpers
static void sep(char c = '-', int w = 56) {
  std::cout << Color::DIM;
  for (int i = 0; i < w; ++i) std::cout << c;
  std::cout << Color::RESET << '\n';
}
static void kv(const std::string& key, const std::string& val,
               const char* col = Color::CYAN) {
  std::cout << Color::DIM << "  " << key;
  int pad = 22 - static_cast<int>(key.size());
  while (pad-- > 0) std::cout << ' ';
  std::cout << Color::RESET << col << val << Color::RESET << '\n';
}

// commands
void cmdIP(const std::string& raw) {
  auto ip = IPv4Address::parse(raw);
  std::cout << '\n' << Color::BOLD << Color::CYAN
            << "  IPv4 Analysis: " << ip.toString()
            << Color::RESET << '\n';
  sep();
  kv("Address:",    ip.toString());
  kv("Binary:",     ip.toBinaryString(), Color::DIM);
  std::ostringstream hex;
  hex << "0x" << std::hex << std::uppercase << ip.value;
  kv("Hex:",        hex.str());
  kv("Decimal:",    std::to_string(ip.value));
  kv("Class:",      ip.rfcClass());
  kv("Type:",       ip.classify(),
     ip.isPrivate() ? Color::GREEN : ip.isMulticast() ? Color::YELLOW : Color::CYAN);
  kv("Loopback:",   ip.isLoopback()  ? "Yes" : "No");
  kv("Multicast:",  ip.isMulticast() ? "Yes" : "No");
  kv("Link-Local:", ip.isLinkLocal() ? "Yes" : "No");
  sep();
  std::cout << '\n';
}
void cmdCIDR(const std::string& raw) {
  auto s = CIDRSubnet::parse(raw);
  std::cout << '\n' << Color::BOLD << Color::CYAN
            << "  CIDR Subnet: " << raw
            << Color::RESET << '\n';
  sep();
  kv("Network:",       s.network.toString() + "/" + std::to_string(s.prefix));
  kv("Subnet Mask:",   s.maskString());
  IPv4Address wc; wc.value = s.wildcardMask();
  kv("Wildcard Mask:", wc.toString());
  kv("Broadcast:",     s.broadcastAddr().toString(), Color::YELLOW);
  kv("First Host:",    s.firstHost().toString(),     Color::GREEN);
  kv("Last Host:",     s.lastHost().toString(),      Color::GREEN);
  kv("Total Hosts:",   std::to_string(s.totalHosts()));
  kv("Class:",         s.network.rfcClass());
  kv("Type:",          s.network.classify());
  sep();
  std::cout << '\n';
}
void cmdScan(const std::string& host, int start, int end) {
  if (start < 1 || end > 65535 || start > end)
    throw std::invalid_argument("Ports must be 1-65535 and start <= end");
  if (end - start > 1023)
    throw std::invalid_argument("Max range per run is 1024 ports");
  std::cout << '\n' << Color::BOLD << Color::CYAN
            << "  TCP Scan: " << host
            << "  [" << start << "-" << end << "]"
            << Color::RESET << '\n';
  sep();
  std::cout << Color::YELLOW
            << "  ! Only scan hosts you own or are authorised to test.\n"
            << Color::RESET;
  sep();
  int openCount = 0;
  for (int p = start; p <= end; ++p) {
    auto r = probePort(host, static_cast<uint16_t>(p));
    if (r.open) {
      ++openCount;
      std::cout << Color::GREEN << "  [OPEN]  " << Color::RESET;
      std::cout.width(6);
      std::cout << std::left << p << "  "
                << Color::CYAN << r.service << Color::RESET << '\n';
    }
  }
  if (openCount == 0)
    std::cout << Color::DIM << "  No open ports found.\n" << Color::RESET;
  sep();
  std::cout << Color::DIM << "  Scanned " << (end - start + 1)
            << " ports - " << openCount << " open.\n"
            << Color::RESET << '\n';
}

// entry point
int main(int argc, char* argv[]) {
  Color::enable();
  std::cout << Color::BOLD << Color::CYAN
            << "\n  CIPH3R Network Analyser  "
            << Color::DIM << "v1.1  (educational)\n"
            << Color::RESET;
  if (argc < 3) {
    std::cout << "\nUsage:\n"
              << "  " << argv[0] << " ip   <address>\n"
              << "  " << argv[0] << " cidr <address/prefix>\n"
              << "  " << argv[0] << " scan <host> <start_port> <end_port>\n\n"
              << "Examples:\n"
              << "  " << argv[0] << " ip 8.8.8.8\n"
              << "  " << argv[0] << " cidr 192.168.1.0/24\n"
              << "  " << argv[0] << " scan localhost 1 1024\n\n";
    return 1;
  }
  try {
    WinsockGuard wsa;
    std::string cmd = argv[1];
    std::transform(cmd.begin(), cmd.end(), cmd.begin(), ::tolower);
    if      (cmd == "ip")   cmdIP(argv[2]);
    else if (cmd == "cidr") cmdCIDR(argv[2]);
    else if (cmd == "scan") {
      if (argc < 5)
        throw std::invalid_argument("scan needs: <host> <start_port> <end_port>");
      cmdScan(argv[2], std::stoi(argv[3]), std::stoi(argv[4]));
    }
    else throw std::invalid_argument("Unknown command: " + cmd);
  } catch (const std::exception& ex) {
    std::cerr << Color::RED << "\n  Error: " << ex.what()
              << Color::RESET << "\n\n";
    return 1;
  }
  return 0;
}
