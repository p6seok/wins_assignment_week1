#include "tcp_session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>

// 전역 세션 리스트 헤드 정의
struct tcp_session *session_list_head = NULL;

// 세션을 찾거나 새로 생성하는 함수
struct tcp_session* find_or_create_session(const char *src_ip, unsigned short src_port, 
                                         const char *dst_ip, unsigned short dst_port) {
    struct tcp_session *current_session = session_list_head;
    
    // 기존 세션이 있는지 확인 (양방향으로 체크)
    while (current_session != NULL) { 
        if ((strcmp(current_session->src_ip_str, src_ip) == 0 && current_session->src_port == src_port &&
             strcmp(current_session->dst_ip_str, dst_ip) == 0 && current_session->dst_port == dst_port) ||
            (strcmp(current_session->src_ip_str, dst_ip) == 0 && current_session->src_port == dst_port &&
             strcmp(current_session->dst_ip_str, src_ip) == 0 && current_session->dst_port == src_port))
        {
            return current_session;
        }
        current_session = current_session->next;
    }

    // 새로운 세션 생성
    struct tcp_session *new_session = (struct tcp_session*)malloc(sizeof(struct tcp_session));
    if (new_session == NULL) {
        fprintf(stderr, "메모리 할당 실패\n");
        return NULL;
    }
    
    // 세션 정보 초기화
    strcpy(new_session->src_ip_str, src_ip);
    new_session->src_port = src_port;
    strcpy(new_session->dst_ip_str, dst_ip);
    new_session->dst_port = dst_port;

    new_session->total_packets = 0;
    new_session->data_transferred = 0;
    new_session->avg_rtt = 0.0;
    new_session->retransmissions = 0;
    timerclear(&new_session->syn_time);
    new_session->handshake_state = 0;
    new_session->seq_count = 0;
    timerclear(&new_session->throughput_start_time);
    new_session->bytes_in_interval = 0;
    
    // 연결리스트에 추가
    new_session->next = session_list_head;
    session_list_head = new_session;

    printf(">>> 새로운 세션 생성: %s:%u <-> %s:%u\n", src_ip, src_port, dst_ip, dst_port);
    return new_session;
}

// 모든 세션 메모리 해제
void free_all_sessions(void) {
    struct tcp_session *current = session_list_head;
    struct tcp_session *next_session;
    
    while (current != NULL) {
        next_session = current->next;
        free(current);
        current = next_session;
    }
    session_list_head = NULL;
}

// 세션 정보 출력 (디버깅용)
void print_session_info(struct tcp_session *session) {
    if (session == NULL) return;
    
    printf("세션: %s:%u <-> %s:%u\n", 
           session->src_ip_str, session->src_port, 
           session->dst_ip_str, session->dst_port);
    printf("  패킷 수: %d, 전송량: %ld bytes, RTT: %.2f ms, 재전송: %d\n",
           session->total_packets, session->data_transferred, 
           session->avg_rtt, session->retransmissions);
}