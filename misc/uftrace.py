import sys
import uftrace_python

sys.setprofile(uftrace_python.trace)

exec(open(sys.argv[1]).read())
