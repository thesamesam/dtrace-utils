/*
 * Oracle Linux DTrace.
 * Copyright (c) 2013, 2024, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

/*
 * ASSERTION:
 * To print errno for failed system calls and make sure it succeeds, and is
 * correct.
 *
 * SECTION: Variables/Built-in Variables
 */

#pragma D option quiet
#pragma D option destructive
#pragma D option zdefs

BEGIN
{
	parent = pid;
	system("cat /non/existant/file");
}

/*
 * Use one clause for syscall::openat:entry and one for syscall::open:entry.
 * Record file name pointer arg1 for the 'openat' function and arg0 for 'open'.
 */
syscall::open:entry
/progenyof(parent)/
{
	self->fn = arg0;  /* 'open' arg0 holds a pointer to the file name */
}

syscall::openat:entry
/progenyof(parent)/
{
	self->fn = arg1;  /* 'openat' arg1 holds a pointer to the file name */
}

syscall::open*:return
/self->fn && copyinstr(self->fn) == "/non/existant/file" && errno != 0/
{
	printf("OPEN FAILED with errno %d\n", errno);
	self->fn = 0;
}

proc:::exit
/progenyof(parent)/
{
	printf("At exit, errno = %d\n", errno);
}

proc:::exit
/progenyof(parent)/
{
	exit(0);
}

ERROR
{
	exit(1);
}
