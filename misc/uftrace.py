import sys
import uftrace_python

sys.argv = sys.argv[1:len(sys.argv)]

code = open(sys.argv[0]).read()
sys.setprofile(uftrace_python.trace)
exec(code)
sys.setprofile(None)
