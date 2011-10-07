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

/*
 * ASSERTION:
 *	Verify shift operators
 *
 * SECTION: Types, Operators, and Expressions/Bitwise Operators;
 * 	Types, Operators, and Expressions/Precedence
 */

#pragma D option quiet


BEGIN
{
	int_1 = 0xffff;

	nint = (((((((((((int_1 << 2 >> 2) << 3 >> 3) << 4 >> 4) << 5 >> 5)
		<< 6 >> 6) << 7 >> 7) << 8 >>8) << 9 >> 9) << 10 >> 10)
		<< 11 >> 11) << 12 >> 12);

}

tick-1
/nint != int_1/
{
	printf("Unexpected error nint = %x, expected %x\n", nint, int_1);
	exit(1);
}

tick-1
/nint == int_1/
{
	exit(0);

}
