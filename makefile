OBJECTS = Process.o Wcry.o FileUtils.o KeyExtractor.o
CC = g++
BOOST_LIB_PATH = C:\boost\include\boost-1_85

KeyExtractor.exe: $(OBJECTS)
	$(CC) $(OBJECTS) -o KeyExtractor.exe -lpsapi 

Process.o: Process.hpp Process.cpp
	$(CC) -c Process.cpp

Wcry.o: Wcry.hpp Wcry.cpp
	$(CC) -c Wcry.cpp

FileUtils.o: FileUtils.hpp FileUtils.cpp
	$(CC) -c FileUtils.cpp

KeyExtractor.o: KeyExtractor.hpp KeyExtractor.cpp
	$(CC) -c KeyExtractor.cpp -I $(BOOST_LIB_PATH)

clean:
	rm -rf *.o KeyExtractor.exe