import sys
import uftrace_python

sys.setprofile(uftrace_python.trace)
sys.argv = sys.argv[1:len(sys.argv)]

exec(open(sys.argv[0]).read())
