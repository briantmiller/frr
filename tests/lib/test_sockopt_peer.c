// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * sockopt_peer_cred() / sockopt_peer_has_gid() tests
 */
#include <zebra.h>

#include "sockopt.h"

int main(int argc, char **argv)
{
	struct sockopt_peer_cred cred;
	int fds[2];

	if (socketpair(AF_UNIX, SOCK_STREAM, 0, fds) < 0) {
		printf("socketpair: %s\n", strerror(errno));
		return 1;
	}

	if (sockopt_peer_cred(fds[0], &cred) < 0) {
		if (errno == EOPNOTSUPP) {
			printf("peer credentials not supported, skipping\n");
			return 0;
		}
		printf("sockopt_peer_cred: %s\n", strerror(errno));
		return 1;
	}

	if (cred.uid != geteuid()) {
		printf("uid mismatch: got %u, expected %u\n", (unsigned int)cred.uid,
		       (unsigned int)geteuid());
		return 1;
	}
	if (cred.gid != getegid()) {
		printf("gid mismatch: got %u, expected %u\n", (unsigned int)cred.gid,
		       (unsigned int)getegid());
		return 1;
	}
	if (cred.pid != -1 && cred.pid != getpid()) {
		printf("pid mismatch: got %ld, expected %ld\n", (long)cred.pid, (long)getpid());
		return 1;
	}

	/* our own primary group is always a match */
	if (!sockopt_peer_has_gid(fds[0], &cred, getegid())) {
		printf("own gid %u not reported as member\n", (unsigned int)getegid());
		return 1;
	}

	/* every supplementary group we hold must match... */
	gid_t mygroups[256];
	int nmy = getgroups(array_size(mygroups), mygroups);

	for (int i = 0; i < nmy; i++)
		if (!sockopt_peer_has_gid(fds[0], &cred, mygroups[i])) {
			printf("supplementary gid %u not reported as member\n",
			       (unsigned int)mygroups[i]);
			return 1;
		}

	/* ...and a group we do not hold must not */
	gid_t other = 54321;
	bool held;

	do {
		held = (other == getegid());
		for (int i = 0; i < nmy; i++)
			held = held || (mygroups[i] == other);
		if (held)
			other++;
	} while (held);

	if (sockopt_peer_has_gid(fds[0], &cred, other)) {
		printf("gid %u wrongly reported as member\n", (unsigned int)other);
		return 1;
	}

	/* not a socket: must fail cleanly */
	if (sockopt_peer_cred(-1, &cred) == 0) {
		printf("expected failure on invalid fd\n");
		return 1;
	}

	close(fds[0]);
	close(fds[1]);
	printf("peer credentials OK\n");
	return 0;
}
