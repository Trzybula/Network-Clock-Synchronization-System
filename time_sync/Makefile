
CXX     = g++
CXXFLAGS = -Wall -Wextra -O2 -std=gnu++17
LFLAGS =

.PHONY: all clean

TARGET1 = peer-time-sync

all: $(TARGET1)

$(TARGET1): peer-time-sync.o err.o
	$(CXX) $(CXXFLAGS) -o $(TARGET1) peer-time-sync.o err.o $(LFLAGS)
peer-time-sync.o: peer-time-sync.cpp peer-time-sync.h err.h
	$(CXX) $(CXXFLAGS) -c peer-time-sync.cpp
err.o: err.cpp err.h
	$(CXX) $(CXXFLAGS) -c err.cpp

clean:
	rm -f $(TARGET1) *.o *~

