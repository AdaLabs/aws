from test_support import *

exec_cmd('wsdl2aws', ['-q', '-f', '-doc', 'anytype.wsdl'])
build_diff('anytype');
