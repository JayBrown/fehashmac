# generate html documentation from README.raw
# and your actual passwd and group files
# a2x is in the Asciidoc package, docbook-xsl.css contains
# the necessary templates
#
# 17.05.2015 hvf
#
# make perftest
# runs a performance test 5 times, calculates the average and produces
# a sorted report.
#
# 11.07.2016 hvf

all:	README.html some.sha1

README.html:	README.txt
	a2x -f xhtml README.txt
	cp -p README.html ..

README.txt:	README.raw some.sha1
	replexec.pl README.raw > README.txt

some.sha1: /etc/passwd /etc/group /dev/null
	sha1 /etc/passwd /etc/group /dev/null > some.sha1

.PHONY:	clean
clean:
	rm -f some.sha1

perftest:	../src/fehashmac
	./mkperftest -n 5

