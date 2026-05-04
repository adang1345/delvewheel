#include <roapi.h>

int main() {
    if (RoInitialize(RO_INIT_MULTITHREADED) == S_OK) {
        RoUninitialize();
    }
    return 0;
}
