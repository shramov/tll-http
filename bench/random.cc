// SPDX-License-Identifier: MIT
// SPDX-FileCopyrightText: Pavel Shramov <shramov@mexmat.net>

#include <tll/util/bench.h>

#include <openssl/rand.h>
#include <stdio.h>
#include <sys/random.h>

using namespace tll::bench;

using namespace std::chrono;

uint64_t libuwsc()
{
	uint64_t buf = 0;

	if (auto fp = fopen("/dev/urandom", "r"); fp) {
		if (fread(&buf, sizeof(buf), 1, fp)) {}
		fclose(fp);
	}
	return buf;
}

uint64_t libc()
{
	uint64_t buf = 0;
	if (getrandom(&buf, sizeof(buf), 0)) {}
	return buf;
}

uint64_t openssl()
{
	uint64_t buf = 0;
	RAND_bytes((unsigned char *) &buf, sizeof(buf));
	return buf;
}

int main()
{
	constexpr size_t count = 100000;
	openssl(); // Call once to initialize internal state
	prewarm(100ms);
	timeit(count / 10, "open(/dev/urandom)", libuwsc);
	timeit(count, "getrandom", libc);
	timeit(count, "RAND_bytes", openssl);

	return 0;
}

