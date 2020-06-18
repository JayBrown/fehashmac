## configure.ac
## autoconf reads this file
## hvf 27.03.06 31.01.2007 02.02.2007 12.02.2007 17.02.2007 19.02.2007
## hvf 25.02.07  06.03.2007 21.10.2008 14.11.2008 17.12.2008
## hvf 07.01.2008: version 1.0.0
## hvf 13.01.2008: version 1.0.1
## hvf 26.01.2008: version 1.0.2
## hvf 04.02.2008: version 1.0.3
## hvf 17.08.2008: version 1.0.4
## hvf 28.03.2011: running autoscan gives additional directives
## hvf 29.03.2011: version 1.1.0
## hvf 07.04.2011: version 1.1.1
## hvf 09.04.2011: version 1.1.2
## hvf 10.04.2011: version 1.1.3
## hvf 11.04.2011: version 1.1.4
## hvf 11.04.2011: version 1.1.5
## hvf 14.04.2011: version 1.1.6
## hvf 01.09.2011: version 1.1.7
## hvf 26.01.2012: version 1.1.8, update AC_CHECK_HEADERS
## hvf 28.01.2012: version 1.2.0
## hvf 07.02.2012: version 1.2.1
## hvf 22.12.2014: modernize AC_INIT and AM_INIT_AUTOMAKE, see automake.pdf
## hvf 27.02.2015: version 1.4.0
## hvf 01.05.2015: version 1.4.1
## hvf 23.05.2015: version 1.4.2
## hvf 12.06.2015: version 1.5.0
## hvf 06.03.2016: Version 1.5.1
## hvf 01.08.2016: Version 2.0  
## hvf 07.09.2016: Version 2.1  

## prerequisite
AC_PREREQ([2.65])

## initialize, give one source code file
## AC_INIT(src/fehashmac.c)

## the package will be called fehashmac-2.1.tar.gz
AC_INIT(fehashmac, 2.1)

AM_INIT_AUTOMAKE


AC_CONFIG_SRCDIR([include/mdx.h])
AC_CONFIG_HEADERS([config.h])

# Checks for programs.
AC_PROG_CXX
AC_PROG_AWK
AC_PROG_CC
AC_PROG_CPP
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_RANLIB

# Checks for libraries.

# Checks for header files.
AC_CHECK_HEADERS([assert.h ctype.h dlfcn.h float.h limits.h \
                  stdarg.h stddef.h stdio.h stdlib.h string.h \
                  sys/resource.h sys/stat.h sys/time.h sys/types.h \
                  time.h unistd.h stdbool.h ])

# Checks for typedefs, structures, and compiler characteristics.
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_CHECK_FUNCS([memset strdup strchr strrchr])

## we need libtools to create libraries
AC_PROG_LIBTOOL

AC_CONFIG_FILES([Makefile
                 lib/Makefile
                 src/Makefile])


## keep correct libtool macros in-tree,
## suggested by libtoolize
AC_CONFIG_MACRO_DIR([m4])

## create this list of Makefiles (we need a Makefile.am in each subdir)
## AC_OUTPUT(Makefile lib/Makefile src/Makefile)
AC_OUTPUT

