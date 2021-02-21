#!/usr/bin/env python3
from __future__ import print_function
import argparse
import bisect
import pefile
import struct
import math
import sys
import os
import re

s = '''{'rip_inst': [], 'code_loc': {69632L: 70335L, 70336L: 70342L, 70344L: 70350L, 70392L: 70398L, 70352L: 70358L, 70376L: 70382L, 70384L: 70390L, 70360L: 70366L, 70368L: 70374L}, 'idata': [], 'bb': [69708L, 69728L, 69910L, 69933L, 69967L, 69975L, 69983L, 69991L, 70022L, 70041L], 'stk_frame': {}, 'relative': {69954L: [70336L, 'e8', 4, 5], 70020L: [70041L, 'eb', 1, 2], 69989L: [70041L, '75', 1, 2], 69706L: [69728L, '74', 1, 2], 69931L: [70041L, '76', 1, 2], 69922L: [70392L, 'e8', 4, 5], 69965L: [70041L, '75', 1, 2], 70034L: [70392L, 'e8', 4, 5], 69651L: [70392L, 'e8', 4, 5], 69908L: [70022L, '75', 1, 2], 69973L: [70041L, '75', 1, 2], 70039L: [70042L, 'eb', 1, 2], 70127L: [70392L, 'e8', 4, 5], 69981L: [70041L, '75', 1, 2], 70015L: [70392L, 'e8', 4, 5]}}'''
ida = None

def load_params():
	global ida
	'''
	todo
	'''
	ida = eval(s.replace('L',''))

if __name__ == '__main__':
#    args = parse_arg()
	load_params()
	