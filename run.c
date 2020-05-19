#include "stdio.h"
int main(){
  printf("main addr=%p\n", main);
  printf("Before breakpoint\n");
  printf("After breakpoint\n");
  printf("final\n");
  return 0;
}