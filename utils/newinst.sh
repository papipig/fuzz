#!/bin/bash

while [ 1 ]
do
	read input
	python -c "import binascii;import sys; sys.stdout.write(binascii.a2b_hex('${input}0000000000'))" > /tmp/x ; ndisasm -b 64 /tmp/x

done