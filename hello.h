#ifndef __HELLO_H
#define __HELLO_H

#define TASK_COMM_LEN 16
#define MAX_DATA_LEN  64

struct event {
	int                pid;
	int                fd;
	unsigned long long count;
	char               comm[TASK_COMM_LEN];
	char               data[MAX_DATA_LEN];
};

#endif