#!/bin/bash

while read input
do
	
	python -c "import binascii;import sys; sys.stdout.write(binascii.a2b_hex('${input}0000000000'))" > /tmp/x ; ndisasm -b 64 /tmp/x | head -1 | sed "s/00000000//g" | sed "s/^  //g" | sed "s/      /  /" | sed "s/  /',  #/"

done