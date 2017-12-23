
CFLAGS=-Wall -g

all: ext2_checker ext2_cp ext2_ln ext2_mkdir ext2_restore ext2_rm

ext2_checker: utils ext2_checker.c ext2_checker.h
	gcc $(CFLAGS) ext2_checker.c ext2_utils.o -o ext2_checker

ext2_cp: utils
	gcc $(CFLAGS) ext2_cp.c ext2_utils.o -o ext2_cp

ext2_ln: utils
	gcc $(CFLAGS) ext2_ln.c ext2_utils.o -o ext2_ln

ext2_mkdir: utils
	gcc $(CFLAGS) ext2_mkdir.c ext2_utils.o -o ext2_mkdir

ext2_restore: utils
	gcc $(CFLAGS) ext2_restore.c ext2_utils.o -o ext2_restore

ext2_rm: utils
	gcc $(CFLAGS) ext2_rm.c ext2_utils.o -o ext2_rm

utils: ext2_utils.c ext2_utils.h
	gcc $(CFLAGS) -c ext2_utils.c

clean:
	rm -f *.o ext2_mkdir ext2_cp ext2_rm ext2_restore ext2_ln ext2_checker *~
