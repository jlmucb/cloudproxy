
ifndef CPProgramDirectory
E=              /home/jlm/jlmcrypt
else
E=              $(CPProgramDirectory)
endif
ifndef VMSourceDirectory
S=              /home/jlm/fpDev/fileProxy/cpvmm
else
S=              $(VMSourceDirectory)
endif
ifndef TARGET_MACHINE_TYPE
TARGET_MACHINE_TYPE= x64
endif

jumpsrc=    	$(S)/vmm/host/hw/em64t

B=              $(E)/vmmobjects/test

CC=         gcc
AS=         as
LINK=       gcc
LIBMAKER=   ar

dobjs=	$(B)/em64t_setjmp.o $(B)/testsetjump.o


all: $(E)/testsetjump.exe
 
$(E)/testsetjump.exe: $(dobjs)
	$(LINK) -o $(E)/testsetjump.exe $(dobjs)

$(B)/testsetjump.o: ./testsetjump.c
	echo "testsetjump.o" 
	$(CC) -c -o $(B)/testsetjump.o ./testsetjump.c

$(B)/em64t_setjmp.o: $(jumpsrc)/em64t_setjmp.s
	echo "em64t_setjmp.o" 
	$(AS) -o $(B)/em64t_setjmp.o $(jumpsrc)/em64t_setjmp.s

