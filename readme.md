#  ssh-snake
Multithreaded Bruteforce ssh scanner written in C

```
IMPORTANT:

This tool is for ethical testing purpose only.
ssh-snake and its owners can't be held responsible for misuse by users.
Users have to act as permitted by local law rules.
````

### Installation
1.) `git clone http://...`
2.) `cd ssh-snake`
3.) `mkdir output`
4.) `make`

### Usage

1.) `touch output/ips.txt` - Add ips separated by new line
2.) `touch output/pass_file` - Add "user pass" combination separated by new line
3.) `cd output`
4.) `./ssh-scan 100` - Be wise with the threads

## Requirements

1.) `gcc`
2.) `libssh`
