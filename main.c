#include <stdio.h>
#include <pcap.h> //libpcap 함수 사용
#include <netinet/ip.h> //IP 헤더 구조체를 위해 포함
#include <netinet/tcp.h> //TCP 헤더 구조체를 위해 포함

struct tcp_session{
    char* src_ip[16];
    char* dst_ip[16];
    int src_port;
    int dst_port;
    int total_packets;
    long data_transferred;
    double avg_rtt;
    int retransmissions;
}

//리포트 요약 출력
void write_report(struct tcp_session *session) {
    FILE *report_file;

    report_file = fopen("reprot.txt","a");
    if (report_file == NULL){
        perror("파일을 열 수 없습니다");
        return;
    }

    fprintf(report_file, "===== Session Summary =====\n");
    fprintf(report_file, "Session: %s:%d <-> %s:%d\n",
        session->src_ip, session->src_port, session->dst_ip, session->dst_port);
    fprintf(report_file, "Total Packet: %ld\n", session->total_packets);
    fprintf(report_file, "Data Transferred: %.2f MB\n", (double)session->data_transferred);
    fprintf(report_file, "Avg RTT: %.2f ms\n", session->retransmissions);
    fprintf(report_file, "===========================\n");

    fclose(report_file);

}