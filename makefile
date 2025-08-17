# TCP Network Analyzer Makefile

# 컴파일러 설정
CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -g
LIBS = -lpcap

# 타겟 실행 파일명
TARGET = tcp_analyzer

# 소스 파일들
SOURCES = main.c tcp_session.c packet_analyzer.c report.c
HEADERS = tcp_session.h packet_analyzer.h report.h

# 오브젝트 파일들
OBJECTS = $(SOURCES:.c=.o)

# 기본 타겟
all: $(TARGET)

# 실행 파일 생성
$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) -o $(TARGET) $(LIBS)
	@echo "빌드 완료: $(TARGET)"

# 오브젝트 파일 생성 규칙
%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

# 청소
clean:
	rm -f $(OBJECTS) $(TARGET) *.txt
	@echo "정리 완료"

# 디버그 빌드
debug: CFLAGS += -DDEBUG -O0
debug: $(TARGET)

# 릴리즈 빌드
release: CFLAGS += -O2 -DNDEBUG
release: $(TARGET)

# 설치 (선택사항)
install: $(TARGET)
	cp $(TARGET) /usr/local/bin/
	@echo "설치 완료: /usr/local/bin/$(TARGET)"

# 테스트 실행 (샘플)
test: $(TARGET)
	@echo "테스트 실행 예시:"
	@echo "sudo ./$(TARGET) live en0 100"
	@echo "./$(TARGET) file sample.pcap"

# 도움말
help:
	@echo "사용 가능한 타겟:"
	@echo "  all      - 기본 빌드"
	@echo "  debug    - 디버그 빌드"
	@echo "  release  - 최적화된 릴리즈 빌드"
	@echo "  clean    - 생성된 파일들 정리"
	@echo "  install  - 시스템에 설치"
	@echo "  test     - 테스트 명령 예시 출력"
	@echo "  help     - 이 도움말 출력"

# 가짜 타겟 (파일과 이름이 같아도 항상 실행)
.PHONY: all clean debug release install test help