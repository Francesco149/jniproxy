#!/usr/bin/env python

import sys
print_lines = False

with open("jniproxy.c", "r") as f:
    for line in f:
        if line.strip().endswith("*/"):
            sys.exit(0);
        if print_lines:
            print(line[4:-1])
        elif line.strip().startswith("/*"):
            print_lines = True
