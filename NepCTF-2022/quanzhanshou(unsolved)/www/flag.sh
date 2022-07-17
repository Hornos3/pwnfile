#!/bin/bash
ulimit -t 55 #max cpu using
ulimit -m 524288 #max memory
ulimit -u 1500 #max process
echo $DASFLAG > /root/flag
./pwn
rm X-admin/flag.txt