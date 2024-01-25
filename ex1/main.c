#include <stdint.h>

uint32_t fibbonacci(uint32_t n) {
	if (n == 0) {
		return 0;
	} else if (n == 1) {
		return 1;
	} else {
		return (fibbonacci(n-1) + fibbonacci(n-2));
	}
}

int main(void)
{

	uint32_t n = 10;
	uint32_t r = 0;
	r = fibbonacci(n);

    return 0;
}