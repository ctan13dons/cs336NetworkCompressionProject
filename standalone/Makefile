PROG = standalone
OBJS = standalone.o

%.o: %.c standalone.h
	gcc -c -g -o $@ $<

$(PROG):$(OBJS)
	gcc -g -o $@ $^

clean: 
	rm -rf $(OBJS) $(PROG)
