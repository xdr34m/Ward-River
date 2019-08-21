#! /usr/bin/env python
#testfile
locallist=[]
test_l=[]
test_l.append(locallist)
test_l[1][0]='eins'
test_l[1][1]='zwei'
for i in range(len(test_l)):
	print test_l
