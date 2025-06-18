#include <iostream>
extern "C" {
#include "simpledll.h"
}

int main()
{
    helloworld();
    std::cout << "Hello world!\n";
    return 0;
}
