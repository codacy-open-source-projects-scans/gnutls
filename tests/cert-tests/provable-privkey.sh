#!/bin/sh

# Copyright (C) 2014 Nikos Mavrogiannopoulos
#
# This file is part of GnuTLS.
#
# GnuTLS is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the
# Free Software Foundation; either version 3 of the License, or (at
# your option) any later version.
#
# GnuTLS is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with GnuTLS.  If not, see <https://www.gnu.org/licenses/>.

#set -e

: ${srcdir=.}
: ${CERTTOOL=../../src/certtool${EXEEXT}}
: ${DIFF=diff}
OUTFILE=provable-privkey$$.tmp

if test "x$ENABLE_DSA" != "x1"; then
	exit 77
fi

if ! test -x "${CERTTOOL}"; then
	exit 77
fi

if ! test -z "${VALGRIND}"; then
	VALGRIND="${LIBTOOL:-libtool} --mode=execute ${VALGRIND}"
fi

#RSA keys
${VALGRIND} "${CERTTOOL}" --verify-provable-privkey --load-privkey "${srcdir}/data/provable2048.pem" &
PID1=$!


${VALGRIND} "${CERTTOOL}" --verify-provable-privkey --load-privkey "${srcdir}/data/provable3072.pem" &
PID2=$!


if test "${FIPS140}" = 1;then
SEED="30:EC:33:4F:97:DB:C0:BA:9C:86:52:A7:B5:D3:F7:B2:DB:BB:48:A4:84:2E:19:0D:21:0E:01:DA:BD:53:59:81:50:37:55:EE:96:A2:70:A5:98:E9:D9:1B:22:54:66:91:69:EB:DF:45:99:D9:F7:2A:CA"
DSAFILE=provable-dsa2048-fips.pem
else
SEED="84:31:21:BD:89:53:5E:E8:69:46:D5:8D:24:6D:47:A5:8D:15:76:A8:35:1B:42:23:E1:CF:F3:69:A1:26:6D:2B:24:B0:72:9D:7C:A5:67:87:FD:E2:E3:DE:19:B9:F2:E7:21:AC:69:8A:29:61:77:32:E7:75:6F:5A:E4:58:0B:E1:79"
DSAFILE=provable-dsa2048.pem
fi

#DSA keys
${VALGRIND} "${CERTTOOL}" --verify-provable-privkey --load-privkey "${srcdir}/data/${DSAFILE}" &
PID3=$!

${VALGRIND} "${CERTTOOL}" --verify-provable-privkey --seed "${SEED}" --load-privkey "${srcdir}/data/${DSAFILE}" &
PID4=$!

wait $PID1
rc1=$?

wait $PID2
rc2=$?

wait $PID3
rc3=$?

wait $PID4
rc4=$?

if test "${rc1}" != "0"; then
	echo "Could not verify the 2048-bit key"
	exit 1
fi

if test "${rc2}" != "0"; then
	echo "Could not verify the 3072-bit key"
	exit 1
fi

if test "${rc3}" != "0"; then
	echo "Could not verify the 2048-bit DSA key"
	exit 1
fi

if test "${rc4}" != "0"; then
	echo "Could not verify the 2048-bit DSA key with explicit seed"
	exit 1
fi

#
# Negative tests, verify using an incorrect seed
#

ARB_SEED="31:EC:34:4F:97:DB:C0:BA:9C:86:52:A7:B5:D3:F7:B2:DB:BB:48:A4:84:2E:19:0D:21:0E:01:DA:BD:53:59:81:50:37:55:EE:96:A2:70:A5:98:E9:D9:1B:22:54:66:91:69:EB:DF:45:99:D9:F7:2A:CA"

${VALGRIND} "${CERTTOOL}" --verify-provable-privkey --seed "${ARB_SEED}" --load-privkey "${srcdir}/data/provable2048.pem" &
PID1=$!

${VALGRIND} "${CERTTOOL}" --verify-provable-privkey --seed "${ARB_SEED}" --load-privkey "${srcdir}/data/${DSAFILE}" &
PID2=$!

wait $PID1
rc1=$?

wait $PID2
rc2=$?

if test "${rc1}" = "0"; then
	echo "Incorrectly verified an RSA key with wrong seed"
	exit 1
fi

if test "${rc2}" = "0"; then
	echo "Incorrectly verified a DSA key with wrong seed"
	exit 1
fi

#
# Try whether re-importing a key loses the parameters
#

"${CERTTOOL}" -k --infile "${srcdir}/data/provable2048.pem"|"${CERTTOOL}" -k|"${CERTTOOL}" -k >${OUTFILE}
grep "Hash: SHA384" ${OUTFILE} && grep "Seed: ab499ea55a5f4cb743434e49ca1ee3a491544309c6f59ab2cd5507de" ${OUTFILE}
if test $? != 0;then
	echo "Could not find validation parameters after re-importing"
	exit 1
fi

rm -f "$OUTFILE"

exit 0
