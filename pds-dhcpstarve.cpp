#include <iostream>
#include <getopt.h>

using namespace std;

int main(int argc, char** argv) {

    int opt;
    while ((opt = getopt (argc, argv, "i")) != -1)
    {
        switch (opt) {
            case 'i':
                printf ("Input file: \"%s\"\n", optarg);
                break;
            default: perror("Wrong arguments");
        }
    }
    cout << "Hello, World!" << std::endl;
    return 0;
}