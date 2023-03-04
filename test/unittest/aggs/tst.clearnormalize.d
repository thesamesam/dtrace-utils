/*
 * Oracle Linux DTrace.
 * Copyright (c) 2006, 2023, Oracle and/or its affiliates. All rights reserved.
 * Licensed under the Universal Permissive License v 1.0 as shown at
 * http://oss.oracle.com/licenses/upl.
 */

/*
 * ASSERTION: Normalized aggregation data can be cleared
 *
 * SECTION: Aggregations/Normalization;
 *	Aggregations/Clearing aggregations
 */
/* @@nosort */
/* @@trigger: periodic_output */

#pragma D option quiet
#pragma D option aggrate=1ms
#pragma D option switchrate=50ms

BEGIN
{
	i = 0;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	printf("Normalized data before clear:\n");
	normalize(@func, 5);
	printa(@func);
	clear(@func);
	n = 0;
}

syscall::write:entry
/pid == $target && n == 2/
{
	printf("Aggregation data after clear:\n");
	printa(@func);
	i++;
}

syscall::write:entry
/pid == $target && n++ == 4/
{
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	@func[i % 5] = sum(i * 100); i++;
	printf("Final (normalized) aggregation data:\n");
	normalize(@func, 5);
	printa(@func);
	exit(0);
}
