#include <stdio.h>
#include <pcap.h> //libpcap 함수 사용
#include <netinet/ip.h> //IP 헤더 구조체를 위해 포함
#include <netinet/tcp.h> //TCP 헤더 구조체를 위해 포함
struct tcp_session *session_list_head = NULL;//세션리스트 시작점, 처음엔 비어있음

struct tcp_session{
    char* src_ip_str[16];
    char* dst_ip_str[16];
    int src_port;
    int dst_port;

    int total_packets;
    long data_transferred;
    double avg_rtt;
    int retransmissions;
    
    struct tcp_session *next;// 다음세션 연결고리
};

void packet_handler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    struct ip *ip_header = (struct ip*)(packet + 14); //주소계산(packet+14) 이후 주소의미 알려주고 새포인터 변수에 저장
    int ip_header_length = ip_header->ip_hl * 4;

    if(ip_header->ip_p != IPPROTO_TCP){
        return;
    }
    //여기서부터 다시코딩해야함
    struct tcphdr *tcp_header = (struct tcphdr *)(packet + 14 + ip_header_length);

    char *src_ip_str = inet_ntoa(ip_header->ip_src);
    char *dst_ip_str = inet_ntoa(ip_header->ip_dst);

    unsigned short src_port = ntohs(tcp_header->th_sport);
    unsigned short dst_port = ntohs(tcp_header->th_dport);

    //테스트용
    printf("TCP Packet: %s:%d -> %s:%d\n", src_ip_str, src_port, dst_ip_str, dst_port);

}

/*
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
    */
    


int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    
    char *filename = "test.pcap"; 

    handle = pcap_open_offline(filename, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "파일을 열 수 없습니다 %s: %s\n", filename, errbuf);
        return(2);
    }

    printf("%s 파일 분석을 시작합니다...\n", filename);
    pcap_loop(handle, 0, packet_handler, NULL); // 0 또는 -1은 파일 끝까지 모두 읽으라는 의미

    pcap_close(handle);

    return(0);
}



// gcc main.c -o main -lpcap (컴파일)
// ./main(실행)