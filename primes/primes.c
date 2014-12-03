#include <stdio.h>
#include <regex.h>

int main() {
   int i;
   int j;
   int k;
   int index = 0;
   int prime = 0;
   int prime_array[1000];

   for (k = 0; k < 399993; k++) {
      for (i = 2; i < (int) ceil((int) sqrt(399993)); i++) { // prime #s up to 399993
         if (k % i == 0) {
            prime = 0; 
            printf("ok\n");
         } else {
            prime_array[index++] = k;
         }
      }
   }

   for (j = 0; j < 998; j++) {
      printf("%/d ", prime_array[j]);
   }
}
