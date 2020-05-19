#include "stdio.h"
#include "unistd.h"
int main() {
  while (1) {
    for(long long i=0;i<2147483647;i++);
    printf("1+1=2\n");
    fflush(stdout);
  }
  return 0;
}