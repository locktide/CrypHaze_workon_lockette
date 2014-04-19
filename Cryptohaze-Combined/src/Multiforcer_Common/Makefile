INCLUDE_ROOT := ../../

include ../../Makefile.inc

CPP_OBJECTS := $(patsubst %.cpp,../../$(OBJDIR)/%.cpp.o,$(wildcard *.cpp))


all: ../../objs $(CPP_OBJECTS)

../../$(OBJDIR)/%.c.o : $(SRCDIR)%.c $(C_DEPS)
	$(VERBOSE)$(CC) $(CFLAGS) -o $@ -c $<

../../$(OBJDIR)/%.cpp.o : $(SRCDIR)%.cpp $(C_DEPS)
	$(VERBOSE)$(CXX) $(CXXFLAGS) -o $@ -c $<

../../objs:
	mkdir -p ../../objs
