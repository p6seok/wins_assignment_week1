#include <stdio.h>

struct Person {
    char* name;
    int age;
};

struct Person p1;
p1.name = "박준석"
p1.age = 29;

struct Person *p1_ptr = &p1;

