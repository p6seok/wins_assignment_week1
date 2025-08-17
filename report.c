#include "report.h"
#include <stdio.h>

// 리포트 파일 초기화 (단순하게)
void initialize_report_file(const char *filename) {
    FILE *report_file = fopen(filename, "w");
    if (report_file == NULL) {
        perror("리포트 파일 초기화 실패");
        return;
    }
    fclose(report_file);
}

// 개별 세션 리포트 작성
void write_session_report(struct tcp_session *session, const char *filename) {
    FILE *report_file = fopen(filename, "a");
    if (report_file == NULL) {
        perror("리포트 파일 열기 실패");
        return;
    }

    fprintf(report_file, "===== Session Summary =====\n");
    fprintf(report_file, "Session: %s:%u <-> %s:%u\n",
            session->src_ip_str, session->src_port,
            session->dst_ip_str, session->dst_port);
    fprintf(report_file, "Total Packets: %d\n", session->total_packets);
    fprintf(report_file, "Data Transferred: %.2f MB\n",
            (double)session->data_transferred / (1024.0 * 1024.0));
    fprintf(report_file, "Avg RTT: %.4f ms\n", session->avg_rtt);
    fprintf(report_file, "Retransmissions: %d\n", session->retransmissions);
    fprintf(report_file, "===========================\n\n");

    fclose(report_file);
}

// 모든 세션의 리포트 작성
void write_all_sessions_report(const char *filename) {
    struct tcp_session *current = session_list_head;
    
    printf("리포트를 %s 파일에 저장합니다.\n", filename);
    
    while (current != NULL) {
        write_session_report(current, filename);
        current = current->next;
    }
}