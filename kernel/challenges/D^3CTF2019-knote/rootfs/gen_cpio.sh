find . -print0 \
| cpio --null -ov --format=newc > $1
