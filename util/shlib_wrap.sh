#!/bin/sh
#dummy implementation of shlib_wrap.sh

export LD_LIBRARY_PATH=../../../..
export DYLD_LIBRARY_PATH=../../../..

cmd="$1"; [ -x "$cmd" ] || cmd="$cmd${EXE_EXT}"
shift
if [ $# -eq 0 ]; then
	exec "$cmd"	# old sh, such as Tru64 4.x, fails to expand empty "$@"
else
	exec "$cmd" "$@"
fi
