#include <stdio.h>

struct Person{
    char* name;
    int age;
};

int main(){
    struct Person p1;
p1.name = "박준석";
p1.age = 29;


struct Person *p1_ptr = &p1;


printf("포인터가 가리키는 이름: %s\n", p1_ptr->name);
printf("포인터가 가리키는 나이: %d\n", p1_ptr->age);
printf("P1의 메모리 주소: %p\n", p1_ptr);

return 0;

}