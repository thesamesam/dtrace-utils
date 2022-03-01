/*
 * Oracle Linux DTrace.
 * Copyright (c) 2021, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

/*
 * ASSERTION: You can't use a pointer to alloca'ed memory if it's been
 *	      modified such that it no longer points there.
 *
 * SECTION: Actions and Subroutines/alloca()
 */

#pragma D option quiet

BEGIN
{
	s = (char *)alloca(10);
        j = s - 1;
	j[1] = 65;
	exit((s[0] == 65 ? 0 : 1) ? 0 : 1);
}

ERROR
{
	exit(1);
}
