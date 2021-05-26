#  ssh-snake
Multi-threaded Bruteforce ssh scanner written in C

```
IMPORTANT:

This tool was written for ethical testing purpose only in a home network.
ssh-snake and its developers can't be held responsible for misuse by users.
Users have to act as permitted by local law rules.
````

### Installation
1. `git clone http://...`
2. `cd ssh-snake`
3. `mkdir output`
4. `make`

### Usage

1.) `touch output/ips.txt` - Add ips separated by new line
2.) `touch output/pass_file` - Add "user pass" combination separated by new line
3.) `cd output`
4.) `./ssh-scan {number of threads} {debug}` - Be wise with the threads. Debug parameter is optional.

## Requirements

1. Linux
2. `gcc`
3. `libssh`
