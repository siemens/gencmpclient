build:
	$(MAKE) -C src all

clean:
	$(MAKE) -C src clean

test:
	./cmpClientDemo
