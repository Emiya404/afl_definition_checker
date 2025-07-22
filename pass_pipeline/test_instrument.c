#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int add(int a, int b) { return a + b; }

int main() {
  printf("the res is %d", add(1, 2));
  return 0;
}
