all: TlbSplitMonitor

clean:
	rm TlbSplitMonitor.o TlbSplitMonitor

TlbSplitMonitor: TlbSplitMonitor.o
	g++ -g -o TlbSplitMonitor TlbSplitMonitor.o

TlbSplitMonitor.o:
	g++ -c -g -O3 -std=c++0x -pg -c -Wall TlbSplitMonitor.cpp