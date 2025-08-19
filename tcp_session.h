#ifndef TCP_SESSION_H
#define TCP_SESSION_H

#include <sys/time.h>
#include <stdint.h>

// TCP 세션 구조체 정의
struct tcp_session {
    // IP 정보
    char src_ip_str[16];
    char dst_ip_str[16];
    unsigned short src_port;
    unsigned short dst_port;

    // 통계 정보
    int total_packets;
    long data_transferred;
    double avg_rtt;
    int retransmissions;
    struct timeval syn_time;
    int handshake_state;

    // RTT 계산용
    double connection_rtt; // 연결수립 RTT
    double data_rtt_sum; //데이터 RTT합
    int data_rtt_count; // 데이터 RTT측정횟수

    // 데이터 RTT 측정용
    uint32_t pending_seq[100]; // 전송 대기중인 SEQ 번호들
    struct timeval seq_times[100]; // 각 SEQ의 전송 시간
    int pending_count; // 대기중인 SEQ개수

    // 재전송 탐지를 위한 SEQ 번호 저장
    uint32_t seen_seq_numbers[2048];
    int seq_count;

    // 처리율 계산을 위한 변수들
    struct timeval throughput_start_time;
    long bytes_in_interval;
    
    struct tcp_session *next; // 연결리스트를 위한 포인터
};

// 전역 세션 리스트 헤드 (extern으로 선언)
extern struct tcp_session *session_list_head;

// 함수 선언
struct tcp_session* find_or_create_session(const char *src_ip, unsigned short src_port, 
                                         const char *dst_ip, unsigned short dst_port);
void free_all_sessions(void);
void print_session_info(struct tcp_session *session);

#endif // TCP_SESSION_H