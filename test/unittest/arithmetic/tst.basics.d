/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2006 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/* @@note: wild negative numbers, tst.basics.d.out does not exist: validate */

/*
 * ASSERTION:
 * 	Simple Arithmetic expressions.
 *	Call simple expressions and make sure test succeeds.
 *	Match expected output in tst.basics.d.out
 *
 * SECTION: Types, Operators, and Expressions/Arithmetic Operators
 *
 */

#pragma D option quiet

BEGIN
{
	i = 0;
	i = 1 + 2 + 3;
	printf("The value of i is %d\n", i);

	i = i * 3;
	printf("The value of i is %d\n", i);

	i = (i * 3) + i;
	printf("The value of i is %d\n", i);

	i = (i + (i * 3) + i) * i;
	printf("The value of i is %d\n", i);

	i = i - (i + (i * 3) + i) * i / i * i;
	printf("The value of i is %d\n", i);

	i = i * (i - 3 + 5 / i * i ) / i * 6;
	printf("The value of i is %d\n", i);

	i = i ^ 5;
	printf("The value of i is %d\n", i);

	exit (0);
}
