#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/ip.h> //ip헤더 구조체를 위해 포함
#include <netinet/tcp.h> //TCP헤더 구조체를 위해 포함
#include <string.h>
#include <stdlib.h>

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
    new_session->next = session_list_head;
    session_list_head = new_session;

    printf(">>> New Session Created: %s:%u <-> %s:%u\n", src_ip, src_port, dst_ip, dst_port);
    return new_session;
}

void packet_handler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14);
    int ip_header_length = ip_header->ip_hl * 4;

    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_length);
    
    //패킷 헤더에서 IP주소랑 포트번호 추출 및 변환
    char *src_ip_str = inet_ntoa(ip_header->ip_src);
    char *dst_ip_str = inet_ntoa(ip_header->ip_dst);
    unsigned short src_port = ntohs(tcp_header->th_sport);
    unsigned short dst_port = ntohs(tcp_header->th_dport);

    //추출한 정보로 추출된 패킷이 속한 세션을 찾거나 새로 생성
    struct tcp_session *session = find_or_create_session(src_ip_str, src_port, dst_ip_str, dst_port);
    
    //세션 통계 정보 업데이트
    session->total_packets++;
    session->data_transferred += ntohs(ip_header->ip_len);
}

//요약파일 생성
void write_report(struct tcp_session *session) {
    FILE *report_file;

    report_file = fopen("report.txt", "a");
    if (report_file == NULL){
        perror("파일을 열 수 없습니다");
        return;
    }

    fprintf(report_file, "===== Session Summary =====\n");
    fprintf(report_file, "Session: %s:%u <-> %s:%u\n",
        session->src_ip_str, session->src_port, session->dst_ip_str, session->dst_port);
    fprintf(report_file, "Total Packets: %d\n", session->total_packets);
    fprintf(report_file, "Data Transferred: %.2f MB\n", (double)session->data_transferred / (1024.0 * 1024.0));
    fprintf(report_file, "Avg RTT: %.2f ms\n", session->avg_rtt);
    fprintf(report_file, "Retransmissions: %d\n", session->retransmissions);
    fprintf(report_file, "===========================\n\n");

    fclose(report_file);
}

//오프라인 pcap파일 불러오기
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *filename = "test.pcap"; 

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

    printf("%s 파일 분석을 시작합니다...\n", filename);
    pcap_loop(handle, 0, packet_handler, NULL);
    pcap_close(handle);

    printf("리포트를 report.txt 파일에 저장합니다...\n");
    struct tcp_session *current = session_list_head;
    struct tcp_session *next_session;
    while (current != NULL) {
        write_report(current);
        next_session = current->next;
        free(current); // 메모리 해제
        current = next_session;
    }
    
    return(0);
}

// gcc main.c -o main -lpcap (컴파일)
// ./main(실행)