PROG = compdetect_server
OBJS = compdetect_server.o

%.o: %.c compdetect_server.h
	gcc -c -g -o $@ $<

$(PROG):$(OBJS)
	gcc -g -o $@ $^

clean:
	rm -rf $(OBJS) $(PROG) config.json
