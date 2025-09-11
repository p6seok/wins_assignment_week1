#include "packet_analyzer.h"
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <stdint.h>

// RTT 계산 함수 (연결 설정 + 데이터 전송 평균)
void calculate_rtt_with_payload(struct tcp_session* session, const struct pcap_pkthdr* pkthdr,
    struct tcphdr* tcp_header, const char* src_ip, int tcp_payload_len) {

    //연결 설정 RTT 계산 (SYN-SYNACK)
    if ((tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK)) {
        // SYN 패킷 (client -> server)
        if (session->handshake_state == 0) {
            printf("DEBUG: SYN packet found for session %s:%u\n", src_ip, ntohs(tcp_header->th_sport));
            session->syn_time = pkthdr->ts;
            session->handshake_state = 1; // SYN 받음
        }
    }
    else if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)) {
        // SYN/ACK 패킷 (server -> client)
        if (session->handshake_state == 1) {
            printf("DEBUG: SYN/ACK packet found. Calculating connection RTT...\n");

            long rtt_us = (pkthdr->ts.tv_sec - session->syn_time.tv_sec) * 1000000 +
                (pkthdr->ts.tv_usec - session->syn_time.tv_usec);

            session->connection_rtt = (double)rtt_us / 1000.0; // ms로 변환
            session->handshake_state = 2; // SYN/ACk 받음, RTT계산완료

            printf("> Connection RTT: %.2f ms\n", session->connection_rtt);

            // 최종 평균 RTT 업데이트
            update_avg_rtt(session);
        }
    }

    //데이터 전송 RTT 계산 (SEQ-ACK)
    else {
        uint32_t seq_num = ntohl(tcp_header->th_seq);
        uint32_t ack_num = ntohl(tcp_header->th_ack);

        // 데이터를 포함한 패킷 (SEQ 추적 시작)
        if (tcp_payload_len > 0 && !(tcp_header->th_flags & TH_ACK)) {
            // SEQ 번호와 시간을 저장 (배열이 가득 차지 않았을때)
            if (session->pending_count < 100) {
                session->pending_seq[session->pending_count] = seq_num;
                session->seq_times[session->pending_count] = pkthdr->ts;
                session->pending_count++;

                printf("DEBUG: Data packet SEQ %u tracked\n", seq_num);
            }
        }

        // ACK 패킷 (대응하는 SEQ 찾아서 RTT 계산)
        if (tcp_header->th_flags & TH_ACK) {
            for (int i = 0; i < session->pending_count; i++) {
                // ACK 번호가 저장된 SEQ + 데이터 길이와 일치하는지 확인
                if (ack_num > session->pending_seq[i]) {
                    // 데이터 RTT 계산
                    long data_rtt_us = (pkthdr->ts.tv_sec - session->seq_times[i].tv_sec) * 1000000 +
                        (pkthdr->ts.tv_usec - session->seq_times[i].tv_usec);

                    double data_rtt_ms = (double)data_rtt_us / 1000.0;

                    // 데이터 RTT 누적
                    session->data_rtt_sum += data_rtt_ms;
                    session->data_rtt_count++;

                    printf("DEBUG: Data RTT calculated: %.2f ms (SEQ %u -> ACK %u)\n",
                        data_rtt_ms, session->pending_seq[i], ack_num);

                    // 처리된 SEQ 제거 (배열에서 삭제)
                    for (int j = i; j < session->pending_count - 1; j++) {
                        session->pending_seq[j] = session->pending_seq[j + 1];
                        session->seq_times[j] = session->seq_times[j + 1];
                    }
                    session->pending_count--;

                    // 최종 평균 RTT 업데이트
                    update_avg_rtt(session);
                    break;
                }
            }
        }
    }
}

// 평균 RTT 계산 함수
void update_avg_rtt(struct tcp_session* session) {
    double total_rtt = 0.0;
    int total_count = 0;

    // 연결 설정 RTT가 있으면 포함
    if (session->connection_rtt > 0) {
        total_rtt += session->connection_rtt;
        total_count++;
    }

    // 데이터 RTT들의 평균을 포함
    if (session->data_rtt_count > 0) {
        double avg_data_rtt = session->data_rtt_sum / session->data_rtt_count;
        total_rtt += avg_data_rtt;
        total_count++;
    }

    // 최종 평균 계산
    if (total_count > 0) {
        session->avg_rtt = total_rtt / total_count;
        printf("> Updated Average RTT for %s:%u: %.2f ms (Connection: %.2f ms, Data avg: %.2f ms)\n",
            session->src_ip_str, session->src_port, session->avg_rtt,
            session->connection_rtt,
            session->data_rtt_count > 0 ? session->data_rtt_sum / session->data_rtt_count : 0.0);
    }
}

// 재전송 탐지 함수
void detect_retransmission(struct tcp_session* session, struct tcphdr* tcp_header,
    int tcp_payload_len) {
    if (tcp_payload_len > 0) {
        uint32_t current_seq = ntohl(tcp_header->th_seq);
        int is_retransmission = 0;

        // 이전에 본 SEQ 번호인지 확인
        for (int i = 0; i < session->seq_count; i++) {
            if (session->seen_seq_numbers[i] == current_seq) {
                is_retransmission = 1;
                break;
            }
        }

        if (is_retransmission) {
            session->retransmissions++;
            printf(">> 재전송 감지 %s:%u (SEQ: %u)\n",
                session->src_ip_str, session->src_port, current_seq);
        }
        else {
            // 새로운 SEQ 번호 저장 (배열이 가득 차지 않은 경우만)
            if (session->seq_count < 2048) {
                session->seen_seq_numbers[session->seq_count] = current_seq;
                session->seq_count++;
            }
        }
    }
}

// 처리율 계산 함수
void calculate_throughput(struct tcp_session* session, const struct pcap_pkthdr* pkthdr,
    int packet_size) {
    // 처리율 측정 시작 시간 설정
    if (session->throughput_start_time.tv_sec == 0) {
        session->throughput_start_time = pkthdr->ts;
    }

    session->bytes_in_interval += packet_size;

    // 1초마다 처리율 계산
    long time_diff_us = (pkthdr->ts.tv_sec - session->throughput_start_time.tv_sec) * 1000000 +
        (pkthdr->ts.tv_usec - session->throughput_start_time.tv_usec);

    if (time_diff_us >= 1000000) { // 1초 경과
        double throughput_kbps = (double)session->bytes_in_interval * 8 /
            (time_diff_us / 1000000.0) / 1000.0;

        printf(">>>> 처리율 %s:%u: %.2f kbps\n",
            session->src_ip_str, session->src_port, throughput_kbps);

        // 다음 측정을 위한 초기화
        session->throughput_start_time = pkthdr->ts;
        session->bytes_in_interval = 0;
    }
}

// 세션 통계 업데이트 함수
void update_session_stats(struct tcp_session* session, int packet_size) {
    session->total_packets++;
    session->data_transferred += packet_size;
}

// 메인 패킷 처리 함수
void packet_handler(u_char* args, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    struct ip* ip_header = (struct ip*)(packet + 14); // 이더넷 헤더 14바이트 제외
    int ip_header_length = ip_header->ip_hl * 4;

    // TCP 패킷이 아닌 경우 무시
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    struct tcphdr* tcp_header = (struct tcphdr*)(packet + 14 + ip_header_length);
    int tcp_header_length = tcp_header->th_off * 4;

    // IP 주소 문자열 변환 (inet_ntoa는 static buffer를 사용하므로 복사 필요)
    char src_ip_buf[16];
    char dst_ip_buf[16];
    strcpy(src_ip_buf, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip_buf, inet_ntoa(ip_header->ip_dst));

    // 포트 번호 추출
    unsigned short src_port = ntohs(tcp_header->th_sport);
    unsigned short dst_port = ntohs(tcp_header->th_dport);

    // 세션 찾기 또는 생성
    struct tcp_session* session = find_or_create_session(src_ip_buf, src_port,
        dst_ip_buf, dst_port);
    if (session == NULL) {
        return; // 메모리 할당 실패
    }

    // 패킷 크기 계산
    int packet_size = ntohs(ip_header->ip_len);
    int tcp_payload_len = packet_size - ip_header_length - tcp_header_length;

    // 세션 통계 업데이트
    update_session_stats(session, packet_size);

    // RTT 계산 (tcp_payload_len도 함께 전달)
    calculate_rtt_with_payload(session, pkthdr, tcp_header, src_ip_buf, tcp_payload_len);

    // 재전송 탐지
    detect_retransmission(session, tcp_header, tcp_payload_len);

    // 처리율 계산
    calculate_throughput(session, pkthdr, packet_size);
}
