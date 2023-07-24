#!/bin/bash
TAGS="tags"
if [ "$1" == "emacs" ];then
	TAGS="TAGS"
fi

make -j$(nproc) ARCH=arm64 ${TAGS} cscope
echo done.
