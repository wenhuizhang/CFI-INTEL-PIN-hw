#include <stdio.h> 
#include <stdint.h>

// A normal function with an int parameter 
// and void return type 
void fun(int a) 
{ 
    printf("Value of a is %d\n", a); 
} 
  
int main() 
{ 
    // fun_ptr is a pointer to function fun()  
    void (*fun_ptr)(int) = &fun; 
  
    /* The above line is equivalent of following two 
       void (*fun_ptr)(int); 
       fun_ptr = &fun;  
    */

    printf("fun_ptr = 0x%lx\n", (int64_t)(&fun));
    printf("main_ptr = 0x%lx\n", (int64_t)(main));
  
    // Invoking fun() using fun_ptr 
    int i;
    for (i=0; i<10; i++) {
      (*fun_ptr)(i); 
    }
  
    return 0; 
} 
