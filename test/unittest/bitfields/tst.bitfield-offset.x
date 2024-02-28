#!/bin/sh
# Licensed under the Universal Permissive License v 1.0 as shown at
# http://oss.oracle.com/licenses/upl.
#
# This is expected to fail on systems where the CTF was built
# with dwarf2ctf.  We can determine this with nothing more than
# objdump, because the CTF version number differs.
#
# Alas objdump cannot read vmlinux.ctfa of this vintage on its
# own: we must embed it into an ELF file ourselves.

ctfa=$tmpdir/vmlinux.ctfa
trap "rm -f $ctfa" EXIT ERR

objcopy --add-section=.ctf=/lib/modules/$(uname -r)/kernel/vmlinux.ctfa /bin/true $ctfa
objdump --ctf=.ctf --ctf-parent=shared_ctf $ctfa |\
    awk '/Version: 3/ { exit 1; } /Version: / { exit 0; }'
