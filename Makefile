CFLAGS = -Wall -std=c11
CLIBS = -lssh -pthread
CSRC = main.c src/thpool.c
OUTDIR = output
OUTNAME = sshscan

all:
	gcc $(CFLAGS) $(CSRC) $(CLIBS) -o $(OUTDIR)/$(OUTNAME)

debug:
	gcc $(CFLAGS) $(CSRC) -D THPOOL_DEBUG $(CLIBS) -o $(OUTNAME)