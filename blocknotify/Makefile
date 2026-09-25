
CXX=g++

CXXFLAGS=-g -O2 -Wall
LDFLAGS=

SOURCES=blocknotify.cpp

OBJECTS=$(SOURCES:.cpp=.o)
OUTPUT=blocknotify

all: $(OUTPUT)

$(OUTPUT): $(OBJECTS)
	$(CXX) $(LDFLAGS) $(OBJECTS) -o $@

.cpp.o:
	$(CXX) $(CXXFLAGS) -c $<

install: all
	strip -s $(OUTPUT)
	mv $(OUTPUT) ../bin/

clean:
	rm -f *.o
	rm -f $(OUTPUT)
