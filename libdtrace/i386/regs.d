/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2012 Oracle, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

inline int R_TRAPNO = 25;
#pragma D binding "1.0" R_TRAPNO
inline int R_GS = 24;
#pragma D binding "1.0" R_GS
inline int R_FS = 23;
#pragma D binding "1.0" R_FS
inline int R_ES = 22;
#pragma D binding "1.0" R_ES
inline int R_DS = 21;
#pragma D binding "1.0" R_DS

inline int R_SS = 20;
#pragma D binding "1.0" R_SS
inline int R_RSP = 19;
#pragma D binding "1.0" R_RSP
inline int R_RFL = 18;
#pragma D binding "1.0" R_RFL
inline int R_CS = 17;
#pragma D binding "1.0" R_CS
inline int R_RIP = 16;
#pragma D binding "1.0" R_RIP
inline int R_ERR = 15;
#pragma D binding "1.0" R_ERR
inline int R_RDI = 14;
#pragma D binding "1.0" R_RDI
inline int R_RSI = 13;
#pragma D binding "1.0" R_RSI
inline int R_RDX = 12;
#pragma D binding "1.0" R_RDX
inline int R_RCX = 11;
#pragma D binding "1.0" R_RCX
inline int R_RAX = 10;
#pragma D binding "1.0" R_RAX
inline int R_R8 = 9;
#pragma D binding "1.0" R_R8
inline int R_R9 = 8;
#pragma D binding "1.0" R_R9
inline int R_R10 = 7;
#pragma D binding "1.0" R_R10
inline int R_R11 = 6;
#pragma D binding "1.0" R_R11
inline int R_RBX = 5;
#pragma D binding "1.0" R_RBX
inline int R_RBP = 4;
#pragma D binding "1.0" R_RBP
inline int R_R12 = 3;
#pragma D binding "1.0" R_R12
inline int R_R13 = 2;
#pragma D binding "1.0" R_R13
inline int R_R14 = 1;
#pragma D binding "1.0" R_R14
inline int R_R15 = 0;
#pragma D binding "1.0" R_R15

inline int R_EBX = R_GS + 1 + 0;
#pragma D binding "1.0" R_EBX
inline int R_ECX = R_GS + 1 + 1;
#pragma D binding "1.0" R_ECX
inline int R_EDX = R_GS + 1 + 2;
#pragma D binding "1.0" R_EDX
inline int R_ESI = R_GS + 1 + 3;
#pragma D binding "1.0" R_ESI
inline int R_EDI = R_GS + 1 + 4;
#pragma D binding "1.0" R_EDI
inline int R_EBP = R_GS + 1 + 5;
#pragma D binding "1.0" R_EBP
inline int R_EAX = R_GS + 1 + 6;
#pragma D binding "1.0" R_EAX
inline int R_EIP = R_GS + 1 + 12;
#pragma D binding "1.0" R_EIP
inline int R_EFL = R_GS + 1 + 14;
#pragma D binding "1.0" R_EFL
inline int R_ESP = R_GS + 1 + 15;
#pragma D binding "1.0" R_ESP

inline int R_PC = R_EIP;
#pragma D binding "1.0" R_PC
inline int R_FP = R_EBP;
#pragma D binding "1.0" R_FP
inline int R_SP = R_ESP;
#pragma D binding "1.0" R_SP
inline int R_PS = R_EFL;
#pragma D binding "1.0" R_PS
inline int R_R0 = R_EAX;
#pragma D binding "1.0" R_R0
inline int R_R1 = R_EBX;
#pragma D binding "1.0" R_R1
