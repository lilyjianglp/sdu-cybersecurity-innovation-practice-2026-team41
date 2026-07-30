CXX := g++
TARGET := fhe_rotation_analysis
SRC := main.cpp

OPENFHE_PREFIX := $(HOME)/opt/openfhe

CXXFLAGS := \
	-O2 \
	-std=c++17 \
	-Wall \
	-Wextra \
	-Wpedantic \
	-fopenmp

CPPFLAGS := \
	-isystem $(OPENFHE_PREFIX)/include/openfhe \
	-isystem $(OPENFHE_PREFIX)/include/openfhe/core \
	-isystem $(OPENFHE_PREFIX)/include/openfhe/pke \
	-isystem $(OPENFHE_PREFIX)/include/openfhe/binfhe

LDFLAGS := \
	-L$(OPENFHE_PREFIX)/lib \
	-Wl,--disable-new-dtags \
	-Wl,-rpath,$(OPENFHE_PREFIX)/lib

LDLIBS := \
	-Wl,--no-as-needed \
	-lOPENFHEpke \
	-lOPENFHEbinfhe \
	-lOPENFHEcore \
	-Wl,--as-needed \
	-pthread \
	-fopenmp

.PHONY: all run clean rebuild check

all: $(TARGET)

$(TARGET): $(SRC)
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(SRC) \
		$(LDFLAGS) $(LDLIBS) -o $(TARGET)

run: $(TARGET)
	LD_LIBRARY_PATH="$(OPENFHE_PREFIX)/lib:$${LD_LIBRARY_PATH}" ./$(TARGET)

check: $(TARGET)
	ldd ./$(TARGET) | grep -E "OPENFHE|not found"

clean:
	rm -f $(TARGET) *.o

rebuild: clean all
