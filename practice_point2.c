/*
#include <stdio.h>
#include <string.h> 

// 플레이어 정보 구조체 (우리가 원하는 데이터)
struct PlayerData {
    int x; // x 좌표
    int y; // y 좌표
    int hp; // 체력
};

// 헤더 구조체 (건너뛰어야 할 데이터)
struct GameHeader {
    int player_id;  // 4바이트
    int packet_type; // 4바이트
}; // 총 8바이트

int main() {
    unsigned char raw_data[20]; 

    // 데이터 묶음에 값 채워넣기 (이 부분은 신경쓰지 마세요)
    struct GameHeader header = { .player_id = 100, .packet_type = 1 };
    struct PlayerData player = { .x = 50, .y = 80, .hp = 95 };
    memcpy(raw_data, &header, sizeof(header));
    memcpy(raw_data + sizeof(header), &player, sizeof(player));
    
    // raw_data의 시작 주소를 가리키는 포인터
    unsigned char *packet_ptr = raw_data;

    // ==================== 여기서부터 코드를 작성하세요 ====================

    // TODO: 
    // 1. struct PlayerData를 가리키는 포인터 변수 'player_info'를 선언하세요.
    // 2. packet_ptr을 이용해 'player_info'가 정확한 위치를 가리키도록
    //    주소 계산 및 형 변환을 한 줄로 작성하세요.

    //struct playerData *player_info = (struct playerData*)(packet_ptr+8); //8인이유는 int변수가 2개있어서
    //GameHeader구조체(int+int)를 건너띄고 PlayerData를 가리켜야한다.
    
    struct playerData *player_info = (struct playerData*)(packet_ptr sizeof(struct GameHeader))
    //가장좋은방법은 sizeof로 건너뛰어야할 범위를 지정하는것. 

    // =================================================================

   
    printf("플레이어의 X 좌표: %d\n", player_info->x);
    printf("플레이어의 Y 좌표: %d\n", player_info->y);
    printf("플레이어의 체력: %d\n", player_info->hp);

    return 0;
}
    */