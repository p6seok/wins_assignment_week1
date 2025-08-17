#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include "tcp_session.h"
#include "packet_analyzer.h"
#include "report.h"

// 메인 함수
int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    char *dev = "en0";
    const char *report_filename = "report.txt";

    // 리포트 파일 초기화
    initialize_report_file(report_filename);

    handle = pcap_open_live(dev, 65536, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "장치 열기 실패 %s: %s\n", dev, errbuf);
        return(2);
    }

    printf("%s 장치에서 실시간 패킷 캡처 시작\n", dev);
    pcap_loop(handle, 1000, packet_handler, NULL); // 1000개 패킷 캡처
    pcap_close(handle);

    printf("리포트를 %s 파일에 저장합니다.\n", report_filename);
    
    write_all_sessions_report(report_filename);
    
    // 메모리 정리
    free_all_sessions();

    return(0);
}