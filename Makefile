CC=g++
OPTIONS=-std=c++11 -ltins -pthread

all:
	$(CC) -o flooding flooding.cpp $(OPTIONS)

clean:
	rm flooding monitor.sh
