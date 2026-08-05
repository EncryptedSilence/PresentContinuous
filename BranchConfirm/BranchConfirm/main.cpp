#include <stdio.h>
#include <stdint.h>
#include <conio.h>
#include <thread>
#include <mutex>
#include <vector>

#define C1 1
#define C2 10
#define C3 15

#define BLOCKSIZE 16
#define WORDNUM 4
#define WORDSZBYTES 4
#define BYTECOUNT 256

#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_RESET   "\x1b[0m"

#define ROTL(a,b) ((a<<b)|(a>>(32-b)))

static inline void lin444_r1(uint32_t* din, uint32_t* dout)
{
	dout[0] = din[0] ^ ROTL(din[1], C1) ^ ROTL(din[2], C2) ^ ROTL(din[3], C3);
	dout[1] = din[1] ^ ROTL(din[2], C1) ^ ROTL(din[3], C2) ^ ROTL(dout[0], C3);
	dout[2] = din[2] ^ ROTL(din[3], C1) ^ ROTL(dout[0], C2) ^ ROTL(dout[1], C3);
	dout[3] = din[3] ^ ROTL(dout[0], C1) ^ ROTL(dout[1], C2) ^ ROTL(dout[2], C3);
}

static inline void  inv_lin444_r1(uint32_t* din, uint32_t* dout)
{
	dout[3] = din[3] ^ ROTL(din[0], C1) ^ ROTL(din[1], C2) ^ ROTL(din[2], C3);
	dout[2] = din[2] ^ ROTL(dout[3], C1) ^ ROTL(din[0], C2) ^ ROTL(din[1], C3);
	dout[1] = din[1] ^ ROTL(dout[2], C1) ^ ROTL(dout[3], C2) ^ ROTL(din[0], C3);
	dout[0] = din[0] ^ ROTL(dout[1], C1) ^ ROTL(dout[2], C2) ^ ROTL(dout[3], C3);
}

void print_data(uint8_t *din, uint8_t *dout)
{
	int wi = 0, wo = 0;
	for (int i = 0;i < BLOCKSIZE;i++) {
		printf("%s%2x ", din[i] ? ANSI_COLOR_GREEN : ANSI_COLOR_RESET, din[i]);
		if (din[i]) wi++;
	}
	printf("\t%sweight: %d\n", ANSI_COLOR_RESET, wi);
	for (int i = 0;i < BLOCKSIZE;i++) {
		printf("%s%2x ", dout[i] ? ANSI_COLOR_GREEN : ANSI_COLOR_RESET, dout[i]);
		if (dout[i]) wo++;
	}
	printf("\t%sweight: %d, branches: %d\n", ANSI_COLOR_RESET, wo, wi + wo);
}

int test1byte(void f(uint32_t*, uint32_t*))
{
	int min = BLOCKSIZE;
	uint8_t din[BLOCKSIZE] = { 0 }, dout[BLOCKSIZE];
	for (int bn1 = 0;bn1 < BLOCKSIZE;bn1++) {
		for (int b1 = 1;b1 < BYTECOUNT;b1++) {
			int res = 1;
			din[bn1] = b1;
			f((uint32_t*)din, (uint32_t*)dout);
			for (int j = 0;j < BLOCKSIZE;j++)
				if (dout[j])
					res++;
			if (res < min) {
				print_data(din, dout);
				min = res;
			}
		}
		din[bn1] = 0;
	}

	return min;
}

int test2bytes(void f(uint32_t*, uint32_t*))
{
	int min = BLOCKSIZE;
	uint8_t din[BLOCKSIZE] = { 0 }, dout[BLOCKSIZE];
	for (int bn1 = 0;bn1 < BLOCKSIZE - 1;bn1++) {
		for (int b1 = 1;b1 < BYTECOUNT;b1++) {
			din[bn1] = b1;
			for (int bn2 = bn1 + 1;bn2 < BLOCKSIZE; bn2++) {
				for (int b2 = 1;b2 < BYTECOUNT;b2++) {
					int res = 2;
					din[bn2] = b2;
					f((uint32_t*)din, (uint32_t*)dout);
					for (int j = 0;j < BLOCKSIZE;j++)
						if (dout[j])
							res++;
					if (res < min) {
						print_data(din, dout);
						min = res;
					}
				}
				din[bn2] = 0;
			}
		}
		din[bn1] = 0;
	}

	return min;
}

int test3bytes(void f(uint32_t*, uint32_t*))
{
	int min = BLOCKSIZE;
	uint8_t din[BLOCKSIZE] = { 0 }, dout[BLOCKSIZE];
	for (int bn1 = 0;bn1 < BLOCKSIZE - 2;bn1++) {
		for (int b1 = 1;b1 < BYTECOUNT;b1++) {
			din[bn1] = b1;
			for (int bn2 = bn1 + 1;bn2 < BLOCKSIZE - 1; bn2++) {
				for (int b2 = 1;b2 < BYTECOUNT;b2++) {
					din[bn2] = b2;
					for (int bn3 = bn2 + 1;bn3 < BLOCKSIZE;bn3++) {
						for (int b3 = 1;b3 < BYTECOUNT;b3++) {
							int res = 3;
							din[bn3] = b3;
							f((uint32_t*)din, (uint32_t*)dout);
							for (int j = 0;j < BLOCKSIZE;j++)
								if (dout[j])
									res++;
							if (res < min) {
								print_data(din, dout);
								min = res;
							}
						}
						din[bn3] = 0;
					}
				}
				din[bn2] = 0;
			}
		}
		din[bn1] = 0;
	}

	return min;
}

int test4bytes(void f(uint32_t*, uint32_t*)) {
	int min = BLOCKSIZE;
	std::mutex min_mutex;

	unsigned num_threads = std::thread::hardware_concurrency();
	if (num_threads == 0) num_threads = 4;
	printf("Using %u threads\n", num_threads);

	auto worker = [&](int b1_start, int b1_end) {
		uint8_t din[BLOCKSIZE] = { 0 }, dout[BLOCKSIZE];
		for (int bn1 = 0; bn1 < BLOCKSIZE - 3; bn1 += 4) {
			for (int bn2 = bn1 + 1; bn2 < BLOCKSIZE - 2; ++bn2) {
				for (int bn3 = bn2 + 1; bn3 < BLOCKSIZE - 1; ++bn3) {
					for (int bn4 = bn3 + 1; bn4 < BLOCKSIZE; ++bn4) {
						for (int b1 = b1_start; b1 < b1_end; ++b1) {
							din[bn1] = b1;
							for (int b2 = 1; b2 < BYTECOUNT; ++b2) {
								din[bn2] = b2;
								for (int b3 = 1; b3 < BYTECOUNT; ++b3) {
									din[bn3] = b3;
									for (int b4 = 1; b4 < BYTECOUNT; ++b4) {
										din[bn4] = b4;
										f((uint32_t*)din, (uint32_t*)dout);
										int res = 4;
										for (int j = 0; j < BLOCKSIZE; ++j)
											if (dout[j]) res++;
										if (res < min) {
											std::lock_guard<std::mutex> lock(min_mutex);
											print_data(din, dout);
											min = res;
										}
										din[bn4] = 0;
									}
									din[bn3] = 0;
								}
								din[bn2] = 0;
							}
							din[bn1] = 0;
						}
					}
				}
			}
		}
		};

	std::vector<std::thread> threads;
	int chunk = BYTECOUNT / num_threads;
	for (unsigned t = 0; t < num_threads; ++t) {
		int start = t * chunk;
		if (!start) start = 1;
		int end = std::min(start + chunk, BYTECOUNT);
		if (start < end)
			threads.emplace_back(worker, start, end);
	}
	for (auto& th : threads) th.join();

	return min;
}

int main()
{
	printf("Coefficients are {%d,%d,%d}\n", C1, C2, C3);
	printf("1 byte forward:\n");
	int res = test1byte(lin444_r1);
	printf("1 byte reverce:\n");
	printf("Min: %d\n", res);
	res = test1byte(inv_lin444_r1);
	printf("Min: %d\n", res);
	printf("2 bytes forward:\n");
	res = test2bytes(lin444_r1);
	printf("Min: %d\n", res);
	printf("2 bytes reverce:\n");
	res = test2bytes(inv_lin444_r1);
	printf("Min: %d\n", res);
	printf("3 bytes forward:\n");
	res = test3bytes(lin444_r1);
	printf("Min: %d\n", res);
	printf("3 bytes reverce:\n");
	res = test3bytes(inv_lin444_r1);
	printf("Min: %d\n", res);
	printf("4 bytes forward:\n");
	res = test4bytes(lin444_r1);
	printf("Min: %d\n", res);

	return 0;
}