CC                   = aarch64-linux-gnu-gcc
AS                   = aarch64-linux-gnu-gcc
LD                   = aarch64-linux-gnu-gcc
CFLAGS              += -D_GNU_SOURCE -O0
INCLUDE              = -I.
LDFLAGS             += $(SUBDIRS:%=-L %) -lpthread

SOURCES              = $(shell ls *.c)
OBJECTS              = $(SOURCES:.c=.o) autogen.o medusa_arm.o
OUTPUT               = app

BUILDDIRS            = $(SUBDIRS:%=build-%)
CLEANDIRS            = $(SUBDIRS:%=clean-%)

.SILENT:
all: $(OUTPUT)

$(OUTPUT): $(BUILDDIRS) $(OBJECTS)
	echo "$(INDENT)[LD]" $(OBJECTS) $(LIBS) -o $(OUTPUT) 
	$(LD) $(OBJECTS) -no-pie  $(LDFLAGS) -o $(OUTPUT) 

%.o : %.c
	echo "$(INDENT)[CC] " $<
	$(CC) $(CFLAGS) $(INCLUDE) -c $<

%.o : %.S
	echo "$(INDENT)[AS] " $<
	$(AS) $(INCLUDE) -c $< -o $@

clean: $(CLEANDIRS)
	echo "$(INDENT)[RM]" $(OBJECTS) $(OUTPUT)
	rm -f $(OBJECTS) $(OUTPUT)
