#include <errno.h>
#include <stdio.h>
#include <unistd.h>
#include <wait.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/syscall.h>
#include <time.h>
#include <string.h>
#include <assert.h>
#include "interceptor.h"
#include <pthread.h>


static int last_child;

int vsyscall_arg(int sno, int n, ...) {

	va_list va;
	long args[6];
	int i, ret;
	
	va_start(va, n);
	for(i = 0; i < n; i++) {
		args[i] = va_arg(va, long);
	}
	va_end(va);
	
	ret = syscall(sno, args[0], args[1], args[2]);
	if(ret) ret = -errno;
	//printf("[%d] ", ret);
	return ret;
}

#define test(s, a, t) \
({\
	int i;\
	char dummy[1024];\
	\
	sprintf(dummy, s, a);\
	printf("test: %s", dummy); \
	for(i=0; i<60-strlen(dummy); i++)\
		putchar('.');\
	if (!(t))\
		printf("failed\n");\
	else\
		printf("passed\n");\
	fflush(stdout);\
})


void clear_log() {
	system("dmesg -c &> /dev/null");
}

/** 
 * Check if the log contains what is expected - if log_message was done properly 
 */
int find_log(long pid, long sno, long *args, long ret) {
	char message[1024], command[1024], output[1024];
	FILE *fp;

	sprintf(message, "[%lx]%lx(%lx,%lx,%lx,%lx,%lx,%lx)", 
	               (long)getpid(), sno, args[0], args[1], args[2], args[3], args[4], args[5]);
	sprintf(command, "dmesg | grep \"\\[%lx\\]%lx(%lx,%lx,%lx,%lx,%lx,%lx)\" 2>&1", 
	               (long)getpid(), sno, args[0], args[1], args[2], args[3], args[4], args[5]);

	fp = popen(command, "r");
	if(!fp)  return -1;

	while(fgets(output, sizeof(output)-1, fp) != NULL) {
		if(strstr(output, message)) {
			pclose(fp);
			return 0;
		}
	}

	pclose(fp);
	return -1;
}

/** 
 * Check if a syscall gets logged properly when it's been already intercepted
 */
int do_monitor(int sysno, int status) {
	int sno, ret, i;
	long args[6];
	
	sno = sysno;
	for(i = 0; i < 6; i++) {
		args[i] = rand();
	}

	ret = syscall(sno, args[0], args[1], args[2], args[3], args[4], args[5]);
	if(ret) ret = -errno;

	//printf("[%x]%lx(%lx,%lx,%lx,%lx,%lx,%lx)\n", getpid(), (long)sysno, 
	//	args[0], args[1], args[2], args[3], args[4], args[5]);

	test("%d nonroot monitor", sysno, find_log(getpid(), (long)sno, args, (long)ret) == status);
	return 0;
}


int do_intercept(int syscall, int status) {
    //printf("do_intercept(%d %d)\n", syscall, status);
	test("%d intercept", syscall, vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_INTERCEPT, syscall, getpid()) == status);
	return 0;
}


int do_release(int syscall, int status) {
    //printf("do_release(%d %d)\n", syscall, status);
	test("%d release", syscall, vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_RELEASE, syscall, getpid()) == status);
	return 0;
}

int do_start(int syscall, int pid, int status) {
	if (pid == -1) {
		pid=getpid();
    }
	test("%d start", syscall, vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_START_MONITORING, syscall, pid) == status);
	return 0;
}

int do_stop(int syscall, int pid, int status) {
	test("%d stop", syscall, vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_STOP_MONITORING, syscall, pid) == status);
	return 0;
}

int do_intercept_silent(int syscall, int status) {
	printf("i");
	return vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_INTERCEPT, syscall, getpid()) == status;
}


int do_release_silent(int syscall, int status) {
	printf("r");
    //printf("do_release(%d %d)\n", syscall, status);
	return vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_RELEASE, syscall, getpid()) == status;
}

int do_start_silent(int syscall, int pid, int status) {
	printf("s");
	if (pid == -1) {
		pid=getpid();
    }
	return vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_START_MONITORING, syscall, pid) == status;
}

int do_stop_silent(int syscall, int pid, int status) {
	printf("t");
	return vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_STOP_MONITORING, syscall, pid) == status;
}





/** 
 * Run the tester as a non-root user, and basically run do_nonroot
 */
void do_as_guest(const char *str, int args1, int args2) {

	char cmd[1024];
	char cmd2[1024];
	char* exec[]={"bash", "-c", cmd2, NULL};

	sprintf(cmd, str, args1, args2);
	sprintf(cmd2, "su nobody -c '%s' ", cmd);
	switch ((last_child = fork()))  {
		case -1:
			assert(0);
		case 0:
			execvp("/bin/bash", exec);
			assert(0);
		default:
			waitpid(last_child, NULL, 0);
	}
}

int do_nonroot(int syscall) {
	do_intercept(syscall, -EPERM);
	do_release(syscall, -EPERM);
	do_start(syscall, 0, -EPERM);
	do_stop(syscall, 0, -EPERM);
	do_start(syscall, 1, -EPERM);
	do_stop(syscall, 1, -EPERM);
	do_start(syscall, getpid(), 0);
	do_start(syscall, getpid(), -EBUSY);
	do_monitor(syscall, 0);
	do_stop(syscall, getpid(), 0);
	do_stop(syscall, getpid(), -EINVAL);
	return 0;
}


void test_syscall(int syscall) {

	//clear_log();
	do_intercept(syscall, 0);
	do_intercept(syscall, -EBUSY);
	do_as_guest("./test_full nonroot %d", syscall, 0);
	do_start(syscall, -2, -EINVAL);
	do_start(syscall, 0, 0);
	do_stop(syscall, 0, 0);
	do_start(syscall, 1, 0);
	do_as_guest("./test_full stop %d 1 %d", syscall, -EPERM);
	do_stop(syscall, 1, 0);
	do_as_guest("./test_full start %d -1 %d", syscall, 0);
	do_stop(syscall, last_child, -EINVAL);
	do_release(syscall, 0);
}

/**
Return 0 for success, -1 otherwise
*/
void *test_syscall_silent(void *syscall) {
	int max_loops;
	int loops;
	int syscall_a;
	int ret;
	syscall_a = (int) syscall;
	ret = 0;

	max_loops = 1000;

	for (loops = 0 ; loops < max_loops ; loops++) {
		ret += do_intercept_silent(syscall_a, 0);
		ret += do_intercept_silent(syscall_a, -EBUSY);
		//do_as_guest("./test_full nonroot %d", syscall, 0);
		ret += do_start_silent(syscall_a, -2, -EINVAL);
		ret += do_start_silent(syscall_a, 0, 0);
		ret += do_stop_silent(syscall_a, 0, 0);
		ret += do_start_silent(syscall_a, 1, 0);
		//do_as_guest("./test_full stop %d 1 %d", syscall, -EPERM);
		ret += do_stop_silent(syscall_a, 1, 0);
		//do_as_guest("./test_full start %d -1 %d", syscall, 0);
		ret += do_stop_silent(syscall_a, last_child, -EINVAL);
		ret += do_release_silent(syscall_a, 0);
	}
	printf("executed %d loops\n", loops);
	pthread_exit((void*)(ret == 9*max_loops ? 0 : -1));
}


int main(int argc, char **argv) {
	int i;
	int bash_pid;
	pthread_t sys_open_thread;
	pthread_t sys_time_thread;
	void *sys_open_ret;
	void *sys_time_ret;

	srand(time(NULL));

	if (argc>1 && strcmp(argv[1], "intercept") == 0) 
		return do_intercept(atoi(argv[2]), atoi(argv[3])); // intercept <syscall> <wanted value>

	if (argc>1 && strcmp(argv[1], "release") == 0)
		return do_release(atoi(argv[2]), atoi(argv[3]));

	if (argc>1 && strcmp(argv[1], "start") == 0)
		return do_start(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));

	if (argc>1 && strcmp(argv[1], "stop") == 0)
		return do_stop(atoi(argv[2]), atoi(argv[3]), atoi(argv[4]));

	if (argc>1 && strcmp(argv[1], "monitor") == 0)
		return do_monitor(atoi(argv[2]), 0);

	if (argc>1 && strcmp(argv[1], "nonroot") == 0)
		return do_nonroot(atoi(argv[2]));

	printf("Running my custom tests (pid=%d)\n", getpid());
	test("insmod interceptor.ko %s", "", system("insmod interceptor.ko") == 0);


	bash_pid = 805;
// do_stop
	//vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_STOP_MONITORING, syscall, pid);

	// Checking invalid system call numbers
	test("intercept_invalid_syscall (-1)%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_INTERCEPT, -1, 0) == -EINVAL);
	test("intercept_invalid_syscall (0)%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_INTERCEPT, 0, 0) == -EINVAL);
	test("intercept_invalid_syscall (338)%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_INTERCEPT, 338, 0) == -EINVAL);
	test("intercept_valid_syscall (336)%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, REQUEST_SYSCALL_INTERCEPT, 336, 0) == 0);

	// Checking invalid commands
	test("try_invalid_cmd (-1)%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, -1, 1, 0) == -EINVAL);
	test("try_invalid_cmd (100)%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, 100, 1, 0) == -EINVAL);

	// Check permissions (-EPERM)
	do_as_guest("./test_full intercept %d %d", SYS_time, -EPERM);
	do_as_guest("./test_full release %d %d", SYS_time, -EPERM);

	printf("Checking permissions for start/stop monitoring\n");
	do_as_guest("./test_full start %d %d -1", SYS_time, bash_pid); // current bash PID from 'ps'
	do_as_guest("./test_full start %d 0 %d", SYS_time, -EPERM);
	do_as_guest("./test_full stop %d %d -1", SYS_time, bash_pid); // current bash PID from 'ps'
	do_as_guest("./test_full stop %d 0 %d", SYS_time, -EPERM);

	// Set up a valid intercept
	printf("Setting up for some tests...\n");
	do_intercept(SYS_time, 0); // Intercepting sys_time
	do_intercept(SYS_time, -EBUSY); // Don't allow intercepting something already intercepted
	do_start(SYS_time, -1, 0); // syscall, pid, status
	do_start(SYS_time, getpid() + 100, -EINVAL); // Invalid pid
	do_start(SYS_time, -1, -EBUSY); // Don't allow monitoring something already monitored
	do_release(SYS_open, -EINVAL); // Don't allow de-intercepting something not intercepted
	do_stop(SYS_open, 0, -EINVAL); // Don't allow stop monitoring on not intercepted
	do_stop(SYS_time, bash_pid, -EINVAL); // Don't allow stop monitoring on not monitored PID
	do_start(SYS_time, bash_pid, 0); // Allow starting monitoring bash
	do_stop(SYS_time, bash_pid, 0); // Allow stopping bash since it was started
	do_release(SYS_time, 0); // Release sys_time

	printf("Intercepting and de-intercepting to check state...\n");
	do_intercept(SYS_open, 0); // Intercept sys_open
	do_start(SYS_open, bash_pid, 0); // Monitor bash pid on open
	do_release(SYS_open, 0); // De-intercept (everything should be cleared);
	do_intercept(SYS_open, 0); // Should be allowed to intercept again
	do_stop(SYS_open, bash_pid, -EINVAL); // Bash should no be monitored here
	do_release(SYS_open, 0); // Should be able to release the system call

	printf("Running professor generic tests:\n");
	test("bad MY_SYSCALL args%s", "",  vsyscall_arg(MY_CUSTOM_SYSCALL, 3, 100, 0, 0) == -EINVAL);
	do_intercept(MY_CUSTOM_SYSCALL, -EINVAL);
	do_release(MY_CUSTOM_SYSCALL, -EINVAL);
	do_intercept(-1, -EINVAL);
	do_release(-1, -EINVAL);
	do_intercept(__NR_exit, 0);
	do_release(__NR_exit, 0);

	printf("Running generic test_syscall on SYS_open...\n");
	test_syscall(SYS_open);
	printf("Running generic test_syscall on SYS_time...\n");
	test_syscall(SYS_time);

	printf("Testing various threads...\n");


	pthread_create(&sys_open_thread, NULL, test_syscall_silent, (void*)SYS_open);
	pthread_create(&sys_time_thread, NULL, test_syscall_silent, (void*)SYS_time);
	pthread_join(sys_open_thread, &sys_open_ret);
	pthread_join(sys_time_thread, &sys_time_ret);

	test("thread SYS_open", "", (int)sys_open_ret == 0);
	test("thread SYS_time", "", (int)sys_time_ret == 0);

	test("rmmod interceptor.ko %s", "", system("rmmod interceptor") == 0);
	return 0;
}

