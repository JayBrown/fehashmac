## Makefile.am
## automake will generate Makefile.in from this file
## hvf 27.03.06 29.03.2011
## hvf 01.02.2012 add testsuite.c timetrial.c
## hvf 01.08.2016 add md5sum2md5, a shell script to convert from md5sum syntax

## define the target that is to be built

bin_PROGRAMS		= fehashmac

## define scripts that are to be installed

bin_SCRIPTS 		= md5sum2md5

## define the source files for each target

fehashmac_SOURCES	= fehashmac.c testvector.c testsuite.c timetrial.c

## define libraries that have to be searched

fehashmac_LDADD		= $(top_builddir)/lib/libfehashmac.la

## define where the include files can be found

INCLUDES		= -I$(top_srcdir)/include

## set CFLAGS

AM_CFLAGS	= -Wall
