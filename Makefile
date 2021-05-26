CFLAGS = -std=c11
CLIBS = -lssh -pthread
CSRC = main.c src/thpool.c src/list.c src/list_iterator.c src/list_node.c src/utils.c
OUTDIR = output
OUTNAME = sshscan

all:
	gcc $(CFLAGS) $(CSRC) $(CLIBS) -o $(OUTDIR)/$(OUTNAME)

debug:
	gcc -Wall $(CFLAGS) $(CSRC) -D THPOOL_DEBUG $(CLIBS) -o $(OUTNAME)
