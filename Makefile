all: monitor injectme.so inject

injectme.so: injectme.c
	gcc injectme.c -o injectme.so --shared -fPIC

inject: inject.c
	gcc inject.c -o inject -ldl -O0

monitor: monitor.c
	gcc monitor.c -o monitor

