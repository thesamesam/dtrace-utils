#!/bin/bash
# 
# Oracle Linux DTrace.
# Copyright (c) 2009, 2023, Oracle and/or its affiliates. All rights reserved.
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.

#
# This tests that cpustat(1) should fail to start if the cpc provider
# is already calling the shots.
#
# This script will fail if:
#       1) The system under test does not define the 'PAPI_tot_ins'
#       generic event.

# @@skip: no cpustat on Linux, and should switch PAPI_tot_ins to cpu-clock

script()
{
	$dtrace $dt_flags -o $dtraceout -s /dev/stdin <<EOF
	#pragma D option bufsize=128k

	cpc:::PAPI_tot_ins-all-10000
	{
		@[probename] = count();
	}
EOF
}

if [ $# != 1 ]; then
	echo expected one argument: '<'dtrace-path'>'
	exit 2
fi

dtrace=$1
dtraceout=/tmp/dtrace.out.$$
script 2>/dev/null &
timeout=15

#
# Sleep while the above script fires into life. To guard against dtrace dying
# and us sleeping forever we allow 15 secs for this to happen. This should be
# enough for even the slowest systems.
#
while [ ! -f $dtraceout ]; do
	sleep 1
	timeout=$(($timeout-1))
	if [ $timeout -eq 0 ]; then
		echo "dtrace failed to start. Exiting."
		exit 1
	fi
done

cpustat -c PAPI_tot_ins 1 5
status=$?

rm $dtraceout

exit $status
