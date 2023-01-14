import sys
import uftrace_python

sys.settrace(uftrace_python.trace)

#execfile(sys.argv[1])
exec(open(sys.argv[1]).read())
