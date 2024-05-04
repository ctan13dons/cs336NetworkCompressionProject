PROG = compdetect_client 
OBJS = compdetect_client.o 

%.o: %.c compdetect_client.h
	gcc -c -g -o $@ $<

$(PROG):$(OBJS)
	gcc -g -o $@ $^

clean: 
	rm -rf $(OBJS) $(PROG)
