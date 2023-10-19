/*
 * Oracle Linux DTrace.
 * Copyright (c) 2023, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

#pragma D option quiet
#pragma D option strsize=14

BEGIN
{
	printf("rindex is %d, should be 0\n", rindex((char *)&`linux_banner, (char *)&`linux_banner));
	exit(0);
}

ERROR
{
	exit(1);
}
