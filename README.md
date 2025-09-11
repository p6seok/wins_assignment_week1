# TCP 네트워크 성능 분석기
## 파일구조
(main.c) : 메인 프로그램
(packet_analyzer.c) / (packet_analyzer.h) : 패킷 분석 모듈
(tcp_session.c / tcp_session.h) : TCP 세션 관리 모듈
(report.c / report.h) : 리포트 생성 모듈
(makefile) : 컴파일용 make 명령어 정의
(.gitignore) : Git 제외 파일 설정

## 과제 목표(나중에 지우기)
1. pcap 파일을 읽을 수 있는 기본 코드 설정 -> 추후에 실시간 탐지로 변경해야함
2. 주요 성능 지표 계산 코드 설정
3. 세션 종료 or 프로그램 종료시 요약 리포트 출력

## 해야할 일
~~1. 성능 계산관련은 네트워크 전공 PDF에서 찾아보기~~
~~2. 라이브러리 공식문서보기~~
~~3. 오프라인 캡쳐파일 분석이랑 실시간 캡쳐후 분석하는 방식 둘다 넣어보기~~
~~4. 모듈화하기 (기존파일은 main_old.c로 변경)~~
~~5. .gitignore 파일 추가하기~~

## 빌드 및 실행
컴파일
bash make

실행
bash sudo ./tcp_analyzer

## 주요기능
- TCP 세션 추적: IP 주소와 포트를 기반으로 세션 식별
- RTT 측정: 3-Way Handshake의 SYN/SYN-ACK 시간차이와 Sequence Number/ACK 시간차이의 평균으로 측정
- 처리율 계산: 1초 간격으로 데이터 전송량 측정
- 재전송 탐지: 중복 SEQ Number 확인으로 재전송 패킷 탐지
- 리포트 생성: 세션별 report.txt 파일에 저장
