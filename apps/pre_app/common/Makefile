MIRACLPATH = miracl
PROXYPATH = proxylib/src
RNGPATH = rng
CC = g++
CCFLAGS = -I${MIRACLPATH} -I${PROXYPATH} -I${RNGPATH} -O2  
CCLIBS = -lstdc++
AR = ar
ARARGS = rcs
PROXYLIB = ${PROXYPATH}/proxylib.a
PROXYLIBWITHMIRACL = ${PROXYPATH}/proxylibmiracl.a
MIRACLLIB = ${MIRACLPATH}/miracl.a 
RNGLIB = ${RNGPATH}/librng.a
 
PP_SERVICE_OBJ = ppservice.o
PP_SERVICE = ppservice

all: ${PP_SERVICE} 

${MIRACLLIB}:
	#cd ${MIRACLPATH}; bash linux; cd -
	#Jet: For my linux 64bits system@20160908
	cd ${MIRACLPATH}; bash linux64; cd -

${PROXYLIB}:
	cd ${PROXYPATH}; make all; cd -

${PP_SERVICE}: ${PP_SERVICE_OBJ} #${PROXYLIBWITHMIRACL} ${PP_SERVICE_OBJ}
	${CC} ${CCFLAGS} ${CCLIBS} -o ${PP_SERVICE} ${PP_SERVICE_OBJ} ${PROXYLIBWITHMIRACL} ${RNGLIB}
 
clean:
	rm -rf *.o ${PP_SERVICE} #${MIRACLLIBRARY} ${PROXYLIB}

%.o: %.c
	${CC} ${CCFLAGS} -c $<

%.o: %.cpp
	${CC} ${CCFLAGS} -c $<

%.h:
