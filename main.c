#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h> //ip헤더 구조체를 위해 포함
#include <netinet/tcp.h> //TCP헤더 구조체를 위해 포함
#include <string.h>
#include <stdlib.h>
#include <sys/time.h> //struct timeval을 위해 포함
#include <stdint.h> // uint32_t를 위해 포함

struct tcp_session {
    //ip
    char src_ip_str[16];
    char dst_ip_str[16];
    unsigned short src_port;
    unsigned short dst_port;

    //요약
    int total_packets;
    long data_transferred;
    double avg_rtt;
    int retransmissions;
    struct timeval syn_time;
    int handshake_state;

    //재전송 탐지
    uint32_t seen_seq_numbers[2048];
    int seq_count;

    //처리율 계산
    struct timeval throughput_start_time; //처리율 측정 시작 시간
    long bytes_in_interval; //측정 간격안에서의 누적바이트수
    
    struct tcp_session *next;// 다음세션 연결고리
};

struct tcp_session *session_list_head = NULL; //연결리스트 시작점, 처음엔 비어있음

struct tcp_session* find_or_create_session(const char *src_ip, unsigned short src_port, const char *dst_ip, unsigned short dst_port) {
    struct tcp_session *current_session = session_list_head;
    
    //tcp 기존세션, 신규세션 동일한지 확인
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

    struct tcp_session *new_session = (struct tcp_session*)malloc(sizeof(struct tcp_session));
    strcpy(new_session->src_ip_str, src_ip);
    new_session->src_port = src_port;
    strcpy(new_session->dst_ip_str, dst_ip);
    new_session->dst_port = dst_port;

    new_session->total_packets = 0;
    new_session->data_transferred = 0;
    new_session->avg_rtt = 0.0;
    new_session->retransmissions = 0;
    timerclear(&new_session->syn_time); //syn_time 0으로 초기화
    new_session->handshake_state = 0; // 핸드셰이크 상태 초기화
    new_session->seq_count = 0;
    timerclear(&new_session->throughput_start_time);
    new_session->bytes_in_interval = 0;
    new_session->next = session_list_head;
    session_list_head = new_session;

    printf(">>> 새로운 세션 생성 : %s:%u <-> %s:%u\n", src_ip, src_port, dst_ip, dst_port);
    return new_session;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);
    int ip_header_length = ip_header->ip_hl * 4;

    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_length);
    int tcp_header_length = tcp_header->th_off*4;

    //inet_ntoa값 복사해두기
    char src_ip_buf[16];
    char dst_ip_buf[16];
    strcpy(src_ip_buf, inet_ntoa(ip_header->ip_src));
    strcpy(dst_ip_buf, inet_ntoa(ip_header->ip_dst));

    //패킷 헤더에서 IP주소랑 포트번호 추출 및 변환
    char *src_ip_str = inet_ntoa(ip_header->ip_src);
    char *dst_ip_str = inet_ntoa(ip_header->ip_dst);
    unsigned short src_port = ntohs(tcp_header->th_sport);
    unsigned short dst_port = ntohs(tcp_header->th_dport);

    //추출한 정보로 추출된 패킷이 속한 세션을 찾거나 새로 생성
    struct tcp_session *session = find_or_create_session(src_ip_buf, src_port, dst_ip_buf, dst_port);
    
    //세션 통계 정보 업데이트
    session->total_packets++;
    session->data_transferred += ntohs(ip_header->ip_len);

    //RTT 계산 코드
    // SYN 패킷 (client -> server)
    if((tcp_header->th_flags & TH_SYN) && !(tcp_header->th_flags & TH_ACK)){
        //최초 SYN이면
        if (session->handshake_state == 0){
            printf("DEBUG: SYN packet found for session %s:%u\n", src_ip_buf, src_port); // 디버깅 라인 추가
            session->syn_time = pkthdr->ts;
            session->handshake_state = 1; // SYN 받음
        }
    }

    //SYNACK 패킷 (server->client)
    else if ((tcp_header->th_flags & TH_SYN) && (tcp_header->th_flags & TH_ACK)){
        if(session->handshake_state == 1){
            printf("DEBUG: SYN/ACK packet found for session %s:%u. Calculating RTT...\n", src_ip_buf, src_port); // 디버깅 라인 추가
            long rtt_us = (pkthdr->ts.tv_sec - session->syn_time.tv_sec) * 1000000 + (pkthdr->ts.tv_usec - session->syn_time.tv_usec);

            session->avg_rtt = (double)rtt_us /1000.0;

            session->handshake_state = 2; //핸드셰이크 완료
            printf("> RTT Calculated for %s:%u: %.2f ms\n", session->src_ip_str, session->src_port, session->avg_rtt);

        }
    }
    //TCP 페이로드 길이 계산
    int tcp_payload_len = ntohs(ip_header->ip_len) - ip_header_length - tcp_header_length;

    if(tcp_payload_len > 0) {
        //SEQ 번호를 네트워크 바이트 순서에서 호스트 순서로 변환
        uint32_t current_seq = ntohl(tcp_header->th_seq);
        int is_retransmission = 0;

        // 이전에 저장되어있는 SEQ 번호인지 확인
        for (int i = 0; i < session->seq_count; i++){
            if(session->seen_seq_numbers[i] == current_seq){
                is_retransmission = 1;
                break;
            }
        }
        if (is_retransmission){
            //재전송이면 카운트증가
            session->retransmissions++;
            printf(">> 재전송 감지 %s:%u\n", session->src_ip_str, session->src_port);
            }

        else{
            if(session->seq_count < 2048){
                session->seen_seq_numbers[session->seq_count] = current_seq;
                session->seq_count++;
            }
        }
    }

    //처리율 계산 코드
    if(session->throughput_start_time.tv_sec == 0){
        session->throughput_start_time = pkthdr->ts;
    }
    session->bytes_in_interval += ntohs(ip_header->ip_len);

    long time_diff_us = (pkthdr->ts.tv_sec - session->throughput_start_time.tv_sec) * 1000000 + 
    (pkthdr->ts.tv_usec - session->throughput_start_time.tv_usec);
    
                        
    if(time_diff_us >=1000000){
        double throughput_kbps = (double)session->bytes_in_interval * 8 / (time_diff_us / 1000000.0) / 1000.0;

        printf(">>>> 처리율 %s:%u: %.2f kbps\n", session->src_ip_str, session->src_port, throughput_kbps);

        session->throughput_start_time = pkthdr->ts;
        session->bytes_in_interval = 0;
    }
    
}

//요약파일 생성
void write_report(struct tcp_session *session) {
    FILE *report_file;
    
    report_file = fopen("report.txt","a");
    if (report_file == NULL){
        perror("파일 열기 실패");
        return;
    }

    fprintf(report_file, "===== Session Summary =====\n");
    fprintf(report_file, "Session: %s:%u <-> %s:%u\n",
        session->src_ip_str, session->src_port, session->dst_ip_str, session->dst_port);
    fprintf(report_file, "Total Packets: %d\n", session->total_packets);
    fprintf(report_file, "Data Transferred: %.2f MB\n", (double)session->data_transferred / (1024.0 * 1024.0));
    fprintf(report_file, "Avg RTT: %.4f ms\n", session->avg_rtt);
    fprintf(report_file, "Retransmissions: %d\n", session->retransmissions);
    fprintf(report_file, "===========================\n\n");

    fclose(report_file);
}

//실시간 캡쳐
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "en0"; //맥북 와이파이 인터페이스

    FILE *fp = fopen("report.txt", "w");
    if (fp != NULL){
        fclose(fp);
    }

    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "장치 열기 실패 %s: %s\n", dev, errbuf);
        return(2);
    }

    printf("%s 장치에서 실시간 패킷 캡쳐 시작\n", dev);
    pcap_loop(handle, 1000, packet_handler, NULL); //-1은 무한캡쳐, 종료가 안돼서 횟수설정함
    pcap_close(handle);

    printf("리포트를 report.txt파일에 저장합니다.\n");
    struct tcp_session *current = session_list_head;
    struct tcp_session *next_session;
    while (current != NULL){
        write_report(current);
        next_session = current->next;
        free(current);
        current = next_session;
    }

    return(0);
}
/*
//오프라인 pcap파일 불러오기
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filename = "test1.pcap"; 

    // 프로그램 시작 시 리포트 파일 초기화
    FILE *fp = fopen("report.txt", "w");
    if (fp != NULL) {
        fclose(fp);
    }

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "파일을 열 수 없습니다 %s: %s\n", filename, errbuf);
        return(2);
    }

    printf("%s 파일 분석을 시작합니다.\n", filename);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    printf("리포트를 report.txt 파일에 저장합니다.\n");
    struct tcp_session *current = session_list_head;
    struct tcp_session *next_session;
    while (current != NULL) {
        write_report(current);
        next_session = current->next;
        free(current); // 메모리 해제
        current = next_session;
    }
    
    return(0);
}*/

// gcc main.c -o main -lpcap (컴파일)
// ./main(실행)