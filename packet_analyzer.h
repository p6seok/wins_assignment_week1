#ifndef PACKET_ANALYZER_H // 만약 이게 정의가 안되었으면 (중복방지)
#define PACKET_ANALYZER_H // 이제 정의합니다

#include <pcap.h>
#include <netinet/tcp.h>
#include "tcp_session.h"

// 패킷 분석 관련 함수들, 구현은 .c 파일로
void packet_handler(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void calculate_rtt_with_payload(struct tcp_session* session, const struct pcap_pkthdr* pkthdr,
    struct tcphdr* tcp_header, const char* src_ip, int tcp_payload_len);
void update_avg_rtt(struct tcp_session* session);
void detect_retransmission(struct tcp_session* session, struct tcphdr* tcp_header,
    int tcp_payload_len);
void calculate_throughput(struct tcp_session* session, const struct pcap_pkthdr* pkthdr,
    int packet_size);
void update_session_stats(struct tcp_session* session, int packet_size);

#endif // PACKET_ANALYZER_H 헤더 가드 끝