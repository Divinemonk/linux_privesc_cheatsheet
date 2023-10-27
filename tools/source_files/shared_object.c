// Compile x64: gcc -shared -o <so_filename> -fPIC shared_object.c
#include <stdio.h>
#include <stdlib.h>

static void inject() __attribute__((constructor));

void inject() {
    // PAYLOAD
}
