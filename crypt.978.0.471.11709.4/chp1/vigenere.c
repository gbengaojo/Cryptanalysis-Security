#include <stdio.h>
#include <stdlib.h>
#include <string.h>



// Usage: crypto key input_file output_file

void main (int argc, char *argv[])
{
   FILE *fi, *fo;
   char *cp;
   int c;

   if ((cp = argv[1]) && *cp != '\0') {
      if ((fi = fopen(argv[2], "rb")) != NULL) {
         if ((fo = fopen(argv[3], "wb")) != NULL) {
            while ((c = getc(fi)) != EOF) {
               if (!*cp) cp = argv[1]; // if we've hit the null bit for the key, cycle...
               c ^= *(cp++);           // XOR input char and key character
               putc(c, fo);            // write that encrypted char to output file
            }
            fclose(fo);
         }
         fclose(fi);
      }
   }
}
