#ifndef REPORT_H
#define REPORT_H

#include "tcp_session.h"

// 리포트 관련 함수들
void initialize_report_file(const char *filename);
void write_session_report(struct tcp_session *session, const char *filename);
void write_all_sessions_report(const char *filename);
void print_session_summary(struct tcp_session *session);

#endif // REPORT_H