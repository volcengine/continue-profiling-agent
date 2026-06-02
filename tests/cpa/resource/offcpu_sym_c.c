// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: 2026 ByteDance

#include <stdio.h>
#include <unistd.h>
#include <time.h>

void offcpu_stage_5()
{
	struct timespec req = { 0, 200 * 1000 * 1000 }; // 200ms
	nanosleep(&req, NULL);
}

void offcpu_stage_4()
{
	offcpu_stage_5();
}

void offcpu_stage_3()
{
	offcpu_stage_4();
}

void offcpu_stage_2()
{
	offcpu_stage_3();
}

void offcpu_stage_1()
{
	offcpu_stage_2();
}

int main()
{
	while (1) {
		offcpu_stage_1();
	}
	return 0;
}
