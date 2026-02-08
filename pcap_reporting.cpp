// pcap_report_universal_ru.cpp
// Универсальный офлайн-анализатор PCAP (C++17 + libpcap) с отчётом НА РУССКОМ.
//
// По умолчанию: статистика только IPv4 (как ты хотел раньше).
// Добавь --ipv6, чтобы учитывать IPv6 тоже.
//
// Сборка:
//   g++ -O2 -std=c++17 pcap_report_universal_ru.cpp -lpcap -o pcap_report
//
// Запуск:
//   ./pcap_report input.pcap --out otchet
//   ./pcap_report input.pcap --out otchet --bpf "tcp"
//   ./pcap_report input.pcap --out otchet --ipv6

#include <pcap.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cinttypes>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using std::string;

#ifndef DLT_EN10MB
#define DLT_EN10MB 1
#endif
#ifndef DLT_NULL
#define DLT_NULL 0
#endif
#ifndef DLT_LOOP
#define DLT_LOOP 108
#endif
#ifndef DLT_RAW
#define DLT_RAW 12
#endif
#ifndef DLT_LINUX_SLL
#define DLT_LINUX_SLL 113
#endif
#ifndef DLT_LINUX_SLL2
#define DLT_LINUX_SLL2 276
#endif
#ifndef DLT_IEEE802_11
#define DLT_IEEE802_11 105
#endif
#ifndef DLT_IEEE802_11_RADIO
#define DLT_IEEE802_11_RADIO 127
#endif
#ifndef DLT_PPP
#define DLT_PPP 9
#endif
#ifndef DLT_PPP_SERIAL
#define DLT_PPP_SERIAL 50
#endif

static inline uint16_t rd16be(const uint8_t* p) {
  uint16_t v;
  std::memcpy(&v, p, sizeof(v));
  return ntohs(v);
}
static inline uint32_t rd32be(const uint8_t* p) {
  uint32_t v;
  std::memcpy(&v, p, sizeof(v));
  return ntohl(v);
}
static inline uint16_t rd16le(const uint8_t* p) {
  return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}
static inline uint32_t rd32le(const uint8_t* p) {
  return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static string mac_to_string(const uint8_t* m) {
  std::ostringstream oss;
  oss << std::hex << std::setfill('0')
      << std::setw(2) << (int)m[0] << ":"
      << std::setw(2) << (int)m[1] << ":"
      << std::setw(2) << (int)m[2] << ":"
      << std::setw(2) << (int)m[3] << ":"
      << std::setw(2) << (int)m[4] << ":"
      << std::setw(2) << (int)m[5];
  return oss.str();
}

static string ipv4_to_string(uint32_t ip_hostorder) {
  struct in_addr a;
  a.s_addr = htonl(ip_hostorder);
  char buf[INET_ADDRSTRLEN]{0};
  inet_ntop(AF_INET, &a, buf, sizeof(buf));
  return string(buf);
}

static string ipv6_to_string(const uint8_t* ip6) {
  char buf[INET6_ADDRSTRLEN]{0};
  inet_ntop(AF_INET6, ip6, buf, sizeof(buf));
  return string(buf);
}

static inline uint64_t ts_to_us(const timeval& tv) {
  return (uint64_t)tv.tv_sec * 1000000ull + (uint64_t)tv.tv_usec;
}

static string json_escape(const string& s) {
  std::ostringstream oss;
  for (char c : s) {
    switch (c) {
      case '\\': oss << "\\\\"; break;
      case '"':  oss << "\\\""; break;
      case '\n': oss << "\\n"; break;
      case '\r': oss << "\\r"; break;
      case '\t': oss << "\\t"; break;
      default:
        if ((unsigned char)c < 0x20) {
          oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
        } else {
          oss << c;
        }
    }
  }
  return oss.str();
}

struct Counter {
  uint64_t packets = 0;
  uint64_t bytes = 0;
  uint64_t payload_bytes = 0;
  void add(uint64_t b, uint64_t pb=0) { packets++; bytes += b; payload_bytes += pb; }
};

struct TcpFlags {
  uint64_t syn=0, ack=0, fin=0, rst=0, psh=0, urg=0, ece=0, cwr=0;
  void add(uint8_t f) {
    if (f & 0x02) syn++;
    if (f & 0x10) ack++;
    if (f & 0x01) fin++;
    if (f & 0x04) rst++;
    if (f & 0x08) psh++;
    if (f & 0x20) urg++;
    if (f & 0x40) ece++;
    if (f & 0x80) cwr++;
  }
};

struct FlowKey {
  string a, b;
  uint16_t pa=0, pb=0;
  uint8_t proto=0;
  bool operator==(const FlowKey& o) const {
    return a==o.a && b==o.b && pa==o.pa && pb==o.pb && proto==o.proto;
  }
};
struct FlowKeyHash {
  size_t operator()(const FlowKey& k) const noexcept {
    std::hash<string> hs;
    size_t h = hs(k.a);
    h ^= (hs(k.b) + 0x9e3779b97f4a7c15ULL + (h<<6) + (h>>2));
    h ^= (size_t)k.pa * 1315423911u + (size_t)k.pb * 2654435761u + (size_t)k.proto;
    return h;
  }
};
struct FlowInfo {
  Counter c;
  uint64_t first_us = 0, last_us = 0;
};

static string proto_name_ru(uint8_t p) {
  switch (p) {
    case 6: return "TCP";
    case 17: return "UDP";
    case 1: return "ICMPv4";
    case 58: return "ICMPv6";
    default: {
      std::ostringstream oss; oss << "IP(" << (int)p << ")";
      return oss.str();
    }
  }
}

static string port_hint_ru(uint8_t proto, uint16_t port) {
  (void)proto;
  switch (port) {
    case 53: return "DNS (имена)";
    case 80: return "HTTP (веб)";
    case 443: return "HTTPS (веб)";
    case 22: return "SSH (администрирование)";
    case 25: return "SMTP (почта)";
    case 110: return "POP3 (почта)";
    case 143: return "IMAP (почта)";
    case 123: return "NTP (время)";
    case 161: return "SNMP (мониторинг)";
    case 389: return "LDAP (каталог)";
    case 445: return "SMB (шары/файлы)";
    case 3389: return "RDP (удалённый рабочий стол)";
    default: return "";
  }
}

static int size_bucket(uint32_t len) {
  if (len <= 63) return 0;
  if (len <= 127) return 1;
  if (len <= 255) return 2;
  if (len <= 511) return 3;
  if (len <= 767) return 4;
  if (len <= 1023) return 5;
  if (len <= 1279) return 6;
  if (len <= 1513) return 7;
  if (len <= 2047) return 8;
  return 9;
}

static string bucket_name_ru(int i) {
  switch (i) {
    case 0: return "0–63";
    case 1: return "64–127";
    case 2: return "128–255";
    case 3: return "256–511";
    case 4: return "512–767";
    case 5: return "768–1023";
    case 6: return "1024–1279";
    case 7: return "1280–1513";
    case 8: return "1514–2047";
    default: return "2048+";
  }
}

struct L3View {
  enum class Kind { NONE, IPV4, IPV6 } kind = Kind::NONE;
  size_t l3_off = 0;
  uint16_t ethertype = 0;
  bool has_srcdst_mac = false;
  string src_mac, dst_mac;
};

static bool parse_80211_llc_snap(const uint8_t* p, size_t caplen, size_t& payload_off, uint16_t& ethertype) {
  if (caplen < 24) return false;
  uint16_t fc = (uint16_t)p[0] | ((uint16_t)p[1] << 8);
  uint8_t type = (fc >> 2) & 0x3;
  uint8_t subtype = (fc >> 4) & 0xF;
  if (type != 2) return false;

  bool toDS   = (fc & (1u << 8)) != 0;
  bool fromDS = (fc & (1u << 9)) != 0;

  size_t hdr = 24;
  if (toDS && fromDS) {
    if (caplen < hdr + 6) return false;
    hdr += 6;
  }
  if (subtype & 0x8) {
    if (caplen < hdr + 2) return false;
    hdr += 2;
  }
  if (caplen < hdr + 8) return false;
  if (p[hdr] != 0xAA || p[hdr+1] != 0xAA || p[hdr+2] != 0x03) return false;
  if (p[hdr+3] != 0x00 || p[hdr+4] != 0x00 || p[hdr+5] != 0x00) return false;

  ethertype = rd16be(p + hdr + 6);
  payload_off = hdr + 8;
  (void)toDS; (void)fromDS;
  return true;
}

static L3View parse_l2(int linktype, const uint8_t* p, size_t caplen) {
  L3View v;

  auto set_kind_by_ethertype = [&](uint16_t et, size_t off) {
    v.ethertype = et;
    v.l3_off = off;
    if (et == 0x0800) v.kind = L3View::Kind::IPV4;
    else if (et == 0x86DD) v.kind = L3View::Kind::IPV6;
    else v.kind = L3View::Kind::NONE;
  };

  if (linktype == DLT_EN10MB) {
    if (caplen < 14) return v;
    v.has_srcdst_mac = true;
    v.dst_mac = mac_to_string(p);
    v.src_mac = mac_to_string(p + 6);
    uint16_t et = rd16be(p + 12);
    size_t off = 14;
    if (et == 0x8100 || et == 0x88A8) {
      if (caplen < off + 4) return v;
      et = rd16be(p + off + 2);
      off += 4;
    }
    set_kind_by_ethertype(et, off);
    return v;
  }

  if (linktype == DLT_LINUX_SLL2) {
    if (caplen < 20) return v;
    uint16_t et = rd16be(p + 0);
    set_kind_by_ethertype(et, 20);
    return v;
  }

  if (linktype == DLT_LINUX_SLL) {
    if (caplen < 16) return v;
    uint16_t et = rd16be(p + 14);
    set_kind_by_ethertype(et, 16);
    return v;
  }

  if (linktype == DLT_NULL || linktype == DLT_LOOP) {
    if (caplen < 4) return v;
    uint32_t fam_le = rd32le(p);
    uint32_t fam_be = ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | (uint32_t)p[3];
    if (fam_le == 2 || fam_be == 2) { v.kind = L3View::Kind::IPV4; v.l3_off = 4; v.ethertype = 0x0800; return v; }
    if (fam_le == 10 || fam_be == 10) { v.kind = L3View::Kind::IPV6; v.l3_off = 4; v.ethertype = 0x86DD; return v; }
    return v;
  }

  if (linktype == DLT_RAW) {
    if (caplen < 1) return v;
    uint8_t ver = (p[0] >> 4) & 0x0F;
    if (ver == 4) { v.kind = L3View::Kind::IPV4; v.l3_off = 0; v.ethertype = 0x0800; }
    else if (ver == 6) { v.kind = L3View::Kind::IPV6; v.l3_off = 0; v.ethertype = 0x86DD; }
    return v;
  }

  if (linktype == DLT_IEEE802_11_RADIO) {
    if (caplen < 4) return v;
    uint16_t rt_len = rd16le(p + 2);
    if (rt_len > caplen) return v;
    size_t off = rt_len;
    uint16_t et = 0;
    size_t pay = 0;
    if (parse_80211_llc_snap(p + off, caplen - off, pay, et)) {
      set_kind_by_ethertype(et, off + pay);
    }
    return v;
  }

  if (linktype == DLT_IEEE802_11) {
    uint16_t et = 0;
    size_t pay = 0;
    if (parse_80211_llc_snap(p, caplen, pay, et)) {
      set_kind_by_ethertype(et, pay);
    }
    return v;
  }

  if (linktype == DLT_PPP || linktype == DLT_PPP_SERIAL) {
    if (caplen < 2) return v;
    uint16_t proto = rd16be(p);
    if (proto == 0x0021) { v.kind = L3View::Kind::IPV4; v.ethertype = 0x0800; v.l3_off = 2; }
    else if (proto == 0x0057) { v.kind = L3View::Kind::IPV6; v.ethertype = 0x86DD; v.l3_off = 2; }
    return v;
  }

  return v;
}

struct Analyzer {
  bool include_ipv6 = false;

  uint64_t total_packets=0, total_bytes=0;
  uint64_t first_us=0, last_us=0;
  int linktype=0;

  Counter l2_total;
  Counter l2_arp;
  Counter l2_unsupported;

  std::unordered_map<string, Counter> mac_stats;

  Counter ipv4, ipv6, other_l3;
  std::unordered_map<string, Counter> ip_stats;
  std::unordered_map<string, Counter> pair_stats;
  std::unordered_map<string, Counter> ipproto_stats;

  Counter tcp, udp, icmp4, icmp6, other_l4;
  std::unordered_map<uint16_t, Counter> tcp_sport, tcp_dport, udp_sport, udp_dport;
  TcpFlags tcp_flags;

  uint64_t dns_packets=0;
  uint64_t http_like_packets=0;

  std::unordered_map<FlowKey, FlowInfo, FlowKeyHash> flows;

  std::array<uint64_t, 10> size_hist{};

  std::unordered_map<string, std::unordered_set<uint16_t>> tcp_ports_per_src;
  std::unordered_map<string, std::unordered_set<string>> dst_hosts_per_src;
  std::unordered_map<string, uint64_t> syn_per_src;
  std::unordered_map<string, uint64_t> synack_per_src;
  std::unordered_map<string, uint64_t> rst_per_src;

  void add_time(uint64_t t) {
    if (total_packets==1) first_us = t;
    last_us = t;
  }

  static FlowKey make_flow(uint8_t proto, const string& src, uint16_t sport,
                           const string& dst, uint16_t dport) {
    FlowKey k;
    k.proto = proto;
    if (src < dst || (src==dst && sport <= dport)) {
      k.a = src; k.pa = sport;
      k.b = dst; k.pb = dport;
    } else {
      k.a = dst; k.pa = dport;
      k.b = src; k.pb = sport;
    }
    return k;
  }

  void add_flow(uint8_t proto, const string& src, uint16_t sport,
                const string& dst, uint16_t dport,
                uint64_t tsus, uint32_t caplen, uint32_t payload_bytes) {
    FlowKey k = make_flow(proto, src, sport, dst, dport);
    auto& f = flows[k];
    if (f.c.packets==0) f.first_us = tsus;
    f.last_us = tsus;
    f.c.add(caplen, payload_bytes);
  }

  template <typename K>
  static std::vector<std::pair<K, Counter>> topN(const std::unordered_map<K, Counter>& m, size_t N) {
    std::vector<std::pair<K, Counter>> v;
    v.reserve(m.size());
    for (auto& kv : m) v.push_back(kv);
    std::sort(v.begin(), v.end(), [](auto& a, auto& b){
      if (a.second.bytes != b.second.bytes) return a.second.bytes > b.second.bytes;
      return a.second.packets > b.second.packets;
    });
    if (v.size() > N) v.resize(N);
    return v;
  }

  static double safe_div(double a, double b) { return (b==0.0) ? 0.0 : (a/b); }

  void handle_ipv4(const uint8_t* ip, uint32_t caplen_frame, uint32_t cap_after_ip) {
    if (cap_after_ip < 20) { ipv4.add(caplen_frame); return; }
    uint8_t ver_ihl = ip[0];
    uint8_t version = (ver_ihl >> 4) & 0x0F;
    uint8_t ihl = (ver_ihl & 0x0F) * 4;
    if (version != 4 || ihl < 20 || cap_after_ip < ihl) { ipv4.add(caplen_frame); return; }

    uint8_t proto = ip[9];
    uint32_t src = rd32be(ip + 12);
    uint32_t dst = rd32be(ip + 16);

    string ssrc = ipv4_to_string(src);
    string sdst = ipv4_to_string(dst);

    ipv4.add(caplen_frame);
    ip_stats[ssrc].add(caplen_frame);
    ip_stats[sdst].add(caplen_frame);
    pair_stats[ssrc + " -> " + sdst].add(caplen_frame);
    ipproto_stats[proto_name_ru(proto)].add(caplen_frame);

    const uint8_t* l4 = ip + ihl;
    uint32_t cap_l4 = cap_after_ip - ihl;

    if (proto == 6) {
      tcp.add(caplen_frame);
      if (cap_l4 < 20) return;
      uint16_t sport = rd16be(l4);
      uint16_t dport = rd16be(l4 + 2);
      uint8_t doff = (l4[12] >> 4) * 4;
      if (doff < 20 || cap_l4 < doff) return;
      uint8_t flags = l4[13];
      tcp_flags.add(flags);

      tcp_sport[sport].add(caplen_frame);
      tcp_dport[dport].add(caplen_frame);

      uint32_t tcp_payload = (cap_l4 > doff) ? (cap_l4 - doff) : 0;
      add_flow(6, ssrc, sport, sdst, dport, last_us, caplen_frame, tcp_payload);

      if (flags & 0x02) syn_per_src[ssrc]++;
      if ((flags & 0x12) == 0x12) synack_per_src[ssrc]++;
      if (flags & 0x04) rst_per_src[ssrc]++;

      tcp_ports_per_src[ssrc].insert(dport);
      dst_hosts_per_src[ssrc].insert(sdst);

      if (tcp_payload >= 4 && (dport == 80 || sport == 80)) {
        const uint8_t* pl = l4 + doff;
        auto is_token = [&](const char* tok) {
          size_t n = std::strlen(tok);
          if (tcp_payload < n) return false;
          return std::memcmp(pl, tok, n) == 0;
        };
        if (is_token("GET ") || is_token("POST") || is_token("HEAD") || is_token("PUT ") || is_token("HTTP")) {
          http_like_packets++;
        }
      }

    } else if (proto == 17) {
      udp.add(caplen_frame);
      if (cap_l4 < 8) return;
      uint16_t sport = rd16be(l4);
      uint16_t dport = rd16be(l4 + 2);

      udp_sport[sport].add(caplen_frame);
      udp_dport[dport].add(caplen_frame);

      uint32_t udp_payload = (cap_l4 > 8) ? (cap_l4 - 8) : 0;
      add_flow(17, ssrc, sport, sdst, dport, last_us, caplen_frame, udp_payload);

      if (sport == 53 || dport == 53) dns_packets++;

    } else if (proto == 1) {
      icmp4.add(caplen_frame);
      add_flow(1, ssrc, 0, sdst, 0, last_us, caplen_frame, cap_l4);

    } else {
      other_l4.add(caplen_frame);
      add_flow(proto, ssrc, 0, sdst, 0, last_us, caplen_frame, cap_l4);
    }
  }

  void handle_ipv6(const uint8_t* ip6, uint32_t caplen_frame, uint32_t cap_after_ip6) {
    if (!include_ipv6) { other_l3.add(caplen_frame); return; }
    if (cap_after_ip6 < 40) { ipv6.add(caplen_frame); return; }
    uint8_t version = (ip6[0] >> 4) & 0x0F;
    if (version != 6) { ipv6.add(caplen_frame); return; }

    uint8_t next = ip6[6];
    string ssrc = ipv6_to_string(ip6 + 8);
    string sdst = ipv6_to_string(ip6 + 24);

    ipv6.add(caplen_frame);
    ip_stats[ssrc].add(caplen_frame);
    ip_stats[sdst].add(caplen_frame);
    pair_stats[ssrc + " -> " + sdst].add(caplen_frame);
    ipproto_stats[proto_name_ru(next)].add(caplen_frame);

    const uint8_t* l4 = ip6 + 40;
    uint32_t cap_l4 = (cap_after_ip6 > 40) ? (cap_after_ip6 - 40) : 0;

    if (next == 6) {
      tcp.add(caplen_frame);
      if (cap_l4 < 20) return;
      uint16_t sport = rd16be(l4);
      uint16_t dport = rd16be(l4 + 2);
      uint8_t doff = (l4[12] >> 4) * 4;
      if (doff < 20 || cap_l4 < doff) return;
      uint8_t flags = l4[13];
      tcp_flags.add(flags);

      tcp_sport[sport].add(caplen_frame);
      tcp_dport[dport].add(caplen_frame);

      uint32_t tcp_payload = (cap_l4 > doff) ? (cap_l4 - doff) : 0;
      add_flow(6, ssrc, sport, sdst, dport, last_us, caplen_frame, tcp_payload);

    } else if (next == 17) {
      udp.add(caplen_frame);
      if (cap_l4 < 8) return;
      uint16_t sport = rd16be(l4);
      uint16_t dport = rd16be(l4 + 2);

      udp_sport[sport].add(caplen_frame);
      udp_dport[dport].add(caplen_frame);

      uint32_t udp_payload = (cap_l4 > 8) ? (cap_l4 - 8) : 0;
      add_flow(17, ssrc, sport, sdst, dport, last_us, caplen_frame, udp_payload);

      if (sport == 53 || dport == 53) dns_packets++;

    } else if (next == 58) {
      icmp6.add(caplen_frame);
      add_flow(58, ssrc, 0, sdst, 0, last_us, caplen_frame, cap_l4);

    } else {
      other_l4.add(caplen_frame);
      add_flow(next, ssrc, 0, sdst, 0, last_us, caplen_frame, cap_l4);
    }
  }

  void consume_packet(const pcap_pkthdr* h, const uint8_t* p) {
    total_packets++;
    total_bytes += h->caplen;
    add_time(ts_to_us(h->ts));
    size_hist[size_bucket(h->caplen)]++;
    l2_total.add(h->caplen);

    L3View v = parse_l2(linktype, p, h->caplen);

    if (v.has_srcdst_mac) {
      mac_stats[v.src_mac].add(h->caplen);
      mac_stats[v.dst_mac].add(h->caplen);
    }

    if (v.ethertype == 0x0806) { l2_arp.add(h->caplen); return; }

    if (v.kind == L3View::Kind::NONE) {
      l2_unsupported.add(h->caplen);
      other_l3.add(h->caplen);
      return;
    }

    if (v.l3_off >= h->caplen) { other_l3.add(h->caplen); return; }
    const uint8_t* l3 = p + v.l3_off;
    uint32_t cap_after_l3 = (uint32_t)(h->caplen - v.l3_off);

    if (v.kind == L3View::Kind::IPV4) handle_ipv4(l3, h->caplen, cap_after_l3);
    else if (v.kind == L3View::Kind::IPV6) handle_ipv6(l3, h->caplen, cap_after_l3);
  }

  string summarize_story_ru() const {
    std::ostringstream oss;
    double dur_s = (last_us > first_us) ? (double)(last_us - first_us)/1e6 : 0.0;
    double pps = safe_div((double)total_packets, dur_s);
    double bps = safe_div((double)total_bytes*8.0, dur_s);

    oss << "Интервал захвата: " << std::fixed << std::setprecision(3) << dur_s << " с. "
        << "Средняя скорость: " << std::setprecision(1) << pps << " пак/с, "
        << std::setprecision(2) << (bps/1e6) << " Мбит/с.\n";

    auto pct = [&](uint64_t part){ return safe_div(100.0*part, (double)total_packets); };

    oss << "Канальный уровень: ARP " << std::setprecision(1) << pct(l2_arp.packets)
        << "%, неподдерживаемые кадры " << pct(l2_unsupported.packets) << "%.\n";

    oss << "Сетевой уровень: IPv4 " << pct(ipv4.packets) << "%";
    if (include_ipv6) oss << ", IPv6 " << pct(ipv6.packets) << "%";
    oss << ".\n";

    oss << "Транспорт: TCP " << pct(tcp.packets) << "%, UDP " << pct(udp.packets)
        << "%, ICMPv4 " << pct(icmp4.packets) << "%";
    if (include_ipv6) oss << ", ICMPv6 " << pct(icmp6.packets) << "%";
    oss << ".\n";

    int suspected = 0;
    for (auto& kv : tcp_ports_per_src) {
      const string& src = kv.first;
      size_t uniq_ports = kv.second.size();
      size_t uniq_hosts = 0;
      auto itH = dst_hosts_per_src.find(src);
      if (itH != dst_hosts_per_src.end()) uniq_hosts = itH->second.size();
      if (uniq_ports >= 50 && uniq_hosts >= 5) {
        if (suspected++ == 0) oss << "Возможна разведка/сканирование портов:\n";
        oss << "  - " << src << ": уникальных портов назначения " << uniq_ports
            << ", уникальных хостов назначения " << uniq_hosts << "\n";
        if (suspected >= 5) break;
      }
    }

    int syn_sus = 0;
    for (auto& kv : syn_per_src) {
      const string& src = kv.first;
      uint64_t syn = kv.second;
      uint64_t synack = 0;
      if (auto it = synack_per_src.find(src); it != synack_per_src.end()) synack = it->second;
      if (syn > 1000 && synack < syn/10) {
        if (syn_sus++ == 0) oss << "Похоже на SYN-шторм/массовые попытки TCP-соединений:\n";
        oss << "  - " << src << ": SYN=" << syn << ", SYN-ACK(от него)=" << synack << "\n";
        if (syn_sus >= 5) break;
      }
    }

    if (dns_packets > 0) {
      oss << "DNS-активность: " << dns_packets << " пакетов с портом 53";
      if (dur_s > 0) oss << " (~" << std::setprecision(1) << (dns_packets/dur_s) << " пак/с)";
      oss << ".\n";
    }
    if (http_like_packets > 0) {
      oss << "HTTP-подобные запросы: " << http_like_packets << " пакетов с сигнатурами HTTP-методов на порту 80.\n";
    }

    auto topIPs = topN(ip_stats, 5);
    if (!topIPs.empty()) {
      oss << "Крупнейшие участники по объёму:\n";
      for (auto& kv : topIPs) {
        double mib = kv.second.bytes / (1024.0*1024.0);
        oss << "  - " << kv.first << ": " << kv.second.packets << " пак, "
            << std::fixed << std::setprecision(2) << mib << " МиБ\n";
      }
    }

    return oss.str();
  }

  void write_txt_ru(const string& path) const {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Невозможно записать файл: " + path);

    double dur_s = (last_us > first_us) ? (double)(last_us - first_us)/1e6 : 0.0;

    out << "ОТЧЁТ ПО PCAP\n";
    out << "=============\n\n";
    out << "Тип канального уровня (DLT): " << linktype << "\n";
    out << "Всего пакетов: " << total_packets << "\n";
    out << "Всего байт:    " << total_bytes << "\n";
    out << "Длительность:  " << std::fixed << std::setprecision(6) << dur_s << " с\n";
    if (dur_s > 0) {
      out << "Средняя скорость (пак/с): " << std::setprecision(2) << (total_packets/dur_s) << "\n";
      out << "Средняя скорость (Мбит/с): " << std::setprecision(2) << ((total_bytes*8.0/dur_s)/1e6) << "\n";
    }
    out << "\n";

    out << "Сводка L2\n---------\n";
    out << "ARP: " << l2_arp.packets << " пак.\n";
    out << "Неподдерживаемые кадры (L2/L3): " << l2_unsupported.packets << " пак.\n\n";

    out << "Сетевой уровень (L3)\n--------------------\n";
    out << "IPv4: " << ipv4.packets << " пак.\n";
    if (include_ipv6) out << "IPv6: " << ipv6.packets << " пак.\n";
    out << "Прочее/отброшено: " << other_l3.packets << " пак.\n\n";

    out << "Транспорт (L4)\n--------------\n";
    out << "TCP:    " << tcp.packets << " пак.\n";
    out << "UDP:    " << udp.packets << " пак.\n";
    out << "ICMPv4: " << icmp4.packets << " пак.\n";
    if (include_ipv6) out << "ICMPv6: " << icmp6.packets << " пак.\n";
    out << "Прочее: " << other_l4.packets << " пак.\n\n";

    out << "Флаги TCP\n---------\n";
    out << "SYN=" << tcp_flags.syn << " ACK=" << tcp_flags.ack
        << " FIN=" << tcp_flags.fin << " RST=" << tcp_flags.rst
        << " PSH=" << tcp_flags.psh << " URG=" << tcp_flags.urg
        << " ECE=" << tcp_flags.ece << " CWR=" << tcp_flags.cwr << "\n\n";

    out << "Распределение размеров пакетов (caplen)\n---------------------------------------\n";
    for (int i=0;i<10;i++) out << std::setw(10) << bucket_name_ru(i) << ": " << size_hist[i] << "\n";
    out << "\n";

    if (!mac_stats.empty()) {
      out << "Топ MAC-адресов по объёму (там, где MAC доступны)\n------------------------------------------------\n";
      for (auto& kv : topN(mac_stats, 20)) {
        out << kv.first << "  пак=" << kv.second.packets << " байт=" << kv.second.bytes << "\n";
      }
      out << "\n";
    }

    out << "Топ IP-адресов по объёму\n------------------------\n";
    for (auto& kv : topN(ip_stats, 20)) {
      out << kv.first << "  пак=" << kv.second.packets << " байт=" << kv.second.bytes << "\n";
    }
    out << "\n";

    out << "Топ направлений (источник -> назначение) по объёму\n--------------------------------------------------\n";
    for (auto& kv : topN(pair_stats, 20)) {
      out << kv.first << "  пак=" << kv.second.packets << " байт=" << kv.second.bytes << "\n";
    }
    out << "\n";

    out << "Топ протоколов IP\n-----------------\n";
    for (auto& kv : topN(ipproto_stats, 20)) {
      out << kv.first << "  пак=" << kv.second.packets << " байт=" << kv.second.bytes << "\n";
    }
    out << "\n";

    auto print_ports = [&](const char* title, const std::unordered_map<uint16_t, Counter>& m, uint8_t proto) {
      out << title << "\n";
      out << std::string(std::strlen(title), '-') << "\n";
      auto v = topN(m, 20);
      for (auto& kv : v) {
        string hint = port_hint_ru(proto, kv.first);
        out << std::setw(5) << kv.first;
        if (!hint.empty()) out << " (" << hint << ")";
        out << "  пак=" << kv.second.packets << " байт=" << kv.second.bytes << "\n";
      }
      out << "\n";
    };

    print_ports("TCP: порты назначения (топ)", tcp_dport, 6);
    print_ports("TCP: порты источника (топ)", tcp_sport, 6);
    print_ports("UDP: порты назначения (топ)", udp_dport, 17);
    print_ports("UDP: порты источника (топ)", udp_sport, 17);

    out << "Потоки (без учёта направления) — топ по объёму\n----------------------------------------------\n";
    struct FlowRow { FlowKey k; FlowInfo f; };
    std::vector<FlowRow> fv;
    fv.reserve(flows.size());
    for (auto& kv : flows) fv.push_back({kv.first, kv.second});
    std::sort(fv.begin(), fv.end(), [](const FlowRow& x, const FlowRow& y){
      if (x.f.c.bytes != y.f.c.bytes) return x.f.c.bytes > y.f.c.bytes;
      return x.f.c.packets > y.f.c.packets;
    });
    size_t lim = std::min<size_t>(50, fv.size());
    for (size_t i=0;i<lim;i++) {
      auto& r = fv[i];
      double fdur = (r.f.last_us > r.f.first_us) ? (double)(r.f.last_us - r.f.first_us)/1e6 : 0.0;
      out << proto_name_ru(r.k.proto) << " "
          << r.k.a << ":" << r.k.pa << " <-> " << r.k.b << ":" << r.k.pb
          << "  пак=" << r.f.c.packets
          << " байт=" << r.f.c.bytes
          << " полезн_байт=" << r.f.c.payload_bytes
          << " длит_потока_с=" << std::fixed << std::setprecision(3) << fdur
          << "\n";
    }
    out << "\n";

    out << "Интерпретация (что происходило)\n--------------------------------\n";
    out << summarize_story_ru() << "\n";
  }

  void write_json_ru(const string& path) const {
    std::ofstream out(path);
    if (!out) throw std::runtime_error("Невозможно записать файл: " + path);

    auto emit_counter = [&](const char* name, const Counter& c) {
      out << "\"" << name << "\":{"
          << "\"пакетов\":" << c.packets << ","
          << "\"байт\":" << c.bytes << ","
          << "\"полезная_нагрузка_байт\":" << c.payload_bytes
          << "}";
    };

    double dur_s = (last_us > first_us) ? (double)(last_us - first_us)/1e6 : 0.0;

    out << "{";
    out << "\"мета\":{"
        << "\"dlt\":" << linktype << ","
        << "\"всего_пакетов\":" << total_packets << ","
        << "\"всего_байт\":" << total_bytes << ","
        << "\"длительность_с\":" << std::fixed << std::setprecision(6) << dur_s << ","
        << "\"учитывать_ipv6\":" << (include_ipv6 ? "true" : "false")
        << "},";

    out << "\"l2\":{";
    emit_counter("arp", l2_arp); out << ",";
    emit_counter("неподдерживаемые", l2_unsupported);
    out << "},";

    out << "\"l3\":{";
    emit_counter("ipv4", ipv4);
    if (include_ipv6) { out << ","; emit_counter("ipv6", ipv6); }
    out << "},";

    out << "\"l4\":{";
    emit_counter("tcp", tcp); out << ",";
    emit_counter("udp", udp); out << ",";
    emit_counter("icmpv4", icmp4);
    if (include_ipv6) { out << ","; emit_counter("icmpv6", icmp6); }
    out << ","; emit_counter("прочее", other_l4);
    out << "},";

    out << "\"флаги_tcp\":{"
        << "\"syn\":" << tcp_flags.syn << ","
        << "\"ack\":" << tcp_flags.ack << ","
        << "\"fin\":" << tcp_flags.fin << ","
        << "\"rst\":" << tcp_flags.rst << ","
        << "\"psh\":" << tcp_flags.psh << ","
        << "\"urg\":" << tcp_flags.urg << ","
        << "\"ece\":" << tcp_flags.ece << ","
        << "\"cwr\":" << tcp_flags.cwr
        << "},";

    out << "\"эвристики\":{"
        << "\"dns_пакетов\":" << dns_packets << ","
        << "\"http_похожих_пакетов\":" << http_like_packets
        << "},";

    out << "\"распределение_размеров\":{";
    for (int i=0;i<10;i++) {
      out << "\"" << json_escape(bucket_name_ru(i)) << "\":" << size_hist[i];
      if (i != 9) out << ",";
    }
    out << "},";

    auto emit_top_map_string = [&](const char* name, const std::unordered_map<string, Counter>& m, size_t N) {
      out << "\"" << name << "\":[";
      auto v = topN(m, N);
      for (size_t i=0;i<v.size();i++) {
        out << "{"
            << "\"ключ\":\"" << json_escape(v[i].first) << "\","
            << "\"пакетов\":" << v[i].second.packets << ","
            << "\"байт\":" << v[i].second.bytes
            << "}";
        if (i+1<v.size()) out << ",";
      }
      out << "]";
    };

    auto emit_top_ports = [&](const char* name, const std::unordered_map<uint16_t, Counter>& m, size_t N, uint8_t proto) {
      out << "\"" << name << "\":[";
      auto v = topN(m, N);
      for (size_t i=0;i<v.size();i++) {
        string hint = port_hint_ru(proto, v[i].first);
        out << "{"
            << "\"порт\":" << v[i].first << ","
            << "\"подсказка\":\"" << json_escape(hint) << "\","
            << "\"пакетов\":" << v[i].second.packets << ","
            << "\"байт\":" << v[i].second.bytes
            << "}";
        if (i+1<v.size()) out << ",";
      }
      out << "]";
    };

    out << "\"топы\":{";
    emit_top_map_string("ip", ip_stats, 50); out << ",";
    emit_top_map_string("направления", pair_stats, 50); out << ",";
    emit_top_map_string("ip_протоколы", ipproto_stats, 50); out << ",";
    emit_top_ports("tcp_порты_назначения", tcp_dport, 50, 6); out << ",";
    emit_top_ports("udp_порты_назначения", udp_dport, 50, 17);
    out << "},";

    out << "\"интерпретация\":\"" << json_escape(summarize_story_ru()) << "\"";

    out << "}\n";
  }
};

static void usage(const char* argv0) {
  std::cerr
    << "Использование: " << argv0 << " <input.pcap> [--out prefix] [--bpf \"expr\"] [--ipv6]\n"
    << "По умолчанию: статистика только IPv4. Добавь --ipv6, чтобы учитывать IPv6.\n"
    << "Примеры:\n"
    << "  " << argv0 << " capture.pcap --out otchet\n"
    << "  " << argv0 << " capture.pcap --out otchet --bpf \"tcp\"\n"
    << "  " << argv0 << " capture.pcap --out otchet --ipv6\n";
}

int main(int argc, char** argv) {
  if (argc < 2) { usage(argv[0]); return 1; }

  string infile = argv[1];
  string outprefix = "otchet";
  string bpf;
  bool include_ipv6 = false;

  for (int i=2;i<argc;i++) {
    string a = argv[i];
    if (a == "--out" && i+1<argc) outprefix = argv[++i];
    else if (a == "--bpf" && i+1<argc) bpf = argv[++i];
    else if (a == "--ipv6") include_ipv6 = true;
    else { usage(argv[0]); return 1; }
  }

  char errbuf[PCAP_ERRBUF_SIZE]{0};
  pcap_t* handle = pcap_open_offline(infile.c_str(), errbuf);
  if (!handle) {
    std::cerr << "Ошибка открытия pcap: " << errbuf << "\n";
    return 2;
  }

  Analyzer az;
  az.include_ipv6 = include_ipv6;
  az.linktype = pcap_datalink(handle);

  if (!bpf.empty()) {
    bpf_program prog;
    if (pcap_compile(handle, &prog, bpf.c_str(), 1, PCAP_NETMASK_UNKNOWN) != 0) {
      std::cerr << "Ошибка pcap_compile: " << pcap_geterr(handle) << "\n";
      pcap_close(handle);
      return 3;
    }
    if (pcap_setfilter(handle, &prog) != 0) {
      std::cerr << "Ошибка pcap_setfilter: " << pcap_geterr(handle) << "\n";
      pcap_freecode(&prog);
      pcap_close(handle);
      return 4;
    }
    pcap_freecode(&prog);
  }

  const u_char* pkt = nullptr;
  pcap_pkthdr* hdr = nullptr;
  int rc;
  while ((rc = pcap_next_ex(handle, &hdr, &pkt)) == 1) {
    az.consume_packet(hdr, pkt);
  }
  if (rc == -1) {
    std::cerr << "Ошибка чтения pcap: " << pcap_geterr(handle) << "\n";
    pcap_close(handle);
    return 5;
  }

  pcap_close(handle);

  try {
    az.write_txt_ru(outprefix + ".txt");
    az.write_json_ru(outprefix + ".json");
  } catch (const std::exception& e) {
    std::cerr << "Ошибка записи отчёта: " << e.what() << "\n";
    return 6;
  }

  std::cout << "Готово: созданы файлы " << outprefix << ".txt и " << outprefix << ".json\n";
  return 0;
}
