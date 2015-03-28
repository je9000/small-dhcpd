CFLAGS=-I/usr/local/include/libnet113/ -W -Wall
LDFLAGS=-lnet -L/usr/local/lib/libnet113 -lpcap
FLAGS_PERL?=/usr/local/bin/perl
OBJS = checksums.o dhcp.o getmac.o handlers.o main.o perlback.o
SRCS = $(OBJS,.o=.c) 

all: dhcpsrv

$(OBJS): $(SRCS)
	$(CC) $(CFLAGS) `${FLAGS_PERL} -MExtUtils::Embed -e ccopts` -c -o $(.TARGET) $(.IMPSRC)

dhcpsrv: $(OBJS)
	$(CC) $(LDFLAGS) `${FLAGS_PERL} -MExtUtils::Embed -e ldopts` -o dhcpsrv $(OBJS)

clean:
	rm -rf *.o dhcpsrv

