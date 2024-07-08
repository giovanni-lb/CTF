
```
Une immense porte sculptée se dresse devant vous. Répondez à ses questions pour accéder au nouveau monde.

Auteur : Abyss Watcher
```

## Challenge Discovery 

For this challenge they are no given file, only an ip:port where we got :

 ```
 \.
 \\      .
  \\ _,.+;)_
  .\\;~%:88%%.
 (( a   `)9,8;%.
 /`   _) ' `9%%%?
(' .-' j    '8%%'
 `"+   |    .88%)+._____..,,_   ,+%$%.
       :.   d%9`             `-%*'"'~%$.
    ___(   (%C                 `.   68%%9
  ."        \7                  ;  C8%%)`
  : ."-.__,'.____________..,`   L.  \86' ,
  : L    : :            `  .'\.   '.  %$9%)
  ;  -.  : |             \  \  "-._ `. `~"
   `. !  : |              )  >     ". ?
     `'  : |            .' .'       : |
         ; !          .' .'         : |
        ,' ;         ' .'           ; (
       .  (         j  (            `  \
       """'          ""'             `"" mh

Chaque valeur de réponse doit être en hexadécimal (paddé sur deux caractères), et séparée par une virgule. Exemple : 0x00,0xAA,0x085F
[1/15] Quelles sont les valeurs des registres x9, x15, x11 après exécution du code assembleur AArch64 suivant : \x49\xcb\x98\xd2\xea\xbd\x88\xd2\xcb\x2f\x8d\xd2\xac\xfd\x94\xd2\x8d\x41\x95\xd2\x0e\xcb\x9c\xd2\x0f\xfc\x91\xd2\xcd\x01\x0e\x8a\xcb\x01\x0a\x8b\x4a\x01\x0a\x8a\x4c\x01\x0a\x8a\x6b\x01\x0e\xca\xcf\x01\x0f\xaa\x8b\x01\x0d\xaa\x6c\x01\x0f\x8a\xcd\x01\x09\xca\xec\x03\x0c\xaa\xc9\x01\x0d\xca\xab\x01\x0a\xca
 ```

We receive some bytecode for 4 differents architectures : `x86` , `x64`, `ARM32` and `AArch64`, and we are asked to return the content or 3 registrers. Both arch and registers are randomly choosen, and we need to do it 15 times to get the flag.

## Solve using Unicorn

For solving this challenge I used the python3 librairy unicorn (https://www.unicorn-engine.org/), in order to emulate a CPU to run the bytecode and then retrieve registry value.

First of all we need to retrieve the data (registry, arch and bytecode) we can do it easly with pwntools librairie
```python
# connect to the challenge
io = remote("challenge.ctf.bzh", 31986)

for i in range(15):
    print(f"Etape : [{i + 1}/15]")
    io.recvuntil(b"registres ")

	# retrieve the registers that we need to return
    reg = io.recvuntil(b"apr").split(b"apr")[0].strip()
    reg = reg.split(b',')
    
    io.recvuntil(b"code assembleur ")

	# retrieve the arch
    arch = io.recvuntil(b"suivant :").split(b" ")[0].strip().decode()

	# retrieve the bytecode and convert it from hex
	bc = io.recvuntil(b"\n").strip()
    code = binascii.unhexlify(bc.replace(b'\\x', b''))

	# call main function to emulate the code and return all reg values
	reg_out = emulate(code, arch)
```

Then we need to setup our emulator in order to run the bytecode in the correct arch and then return registers values :

```python
def emulate(code, arch):
    BASE_ADDRESS = 0x10000

	# init the emulator for the given arch
    mu = init_unicorn(arch)

	# Map 2 Mb of memory and write the given bytecode to it
    mu.mem_map(BASE_ADDRESS, 2 * 1024 * 1024)
    mu.mem_write(BASE_ADDRESS, shellcode)

	# Start the emulator
    mu.emu_start(BASE_ADDRESS, BASE_ADDRESS + len(code))

	# Read all registers from the emulator after it run
    return read_registers(mu, arch)

```

the `init_unicorn(arch)` is just a function that with a given arch choose the right parameter for setup.
```python
def init_unicorn(arch):
    arch_dict = {
        'x86': (UC_ARCH_X86, UC_MODE_32),
        'x64': (UC_ARCH_X86, UC_MODE_64),
        'ARM32': (UC_ARCH_ARM, UC_MODE_ARM),
        'AArch64': (UC_ARCH_ARM64, UC_MODE_ARM)
    }
    if arch in arch_dict:
        return Uc(*arch_dict[arch])
    else:
        raise ValueError(f"Architecture not implemented: {arch}")
```

`read_registers(mu, arch)` as it name say only read all registers from a given emulator `mu` running on a given architecture `arch`

```python
def read_registers(mu, arch):
	# Create a map with all registry we need for each arch on this challenge
    reg_map = {
        'x86': [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX],
        'x64': [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX],
        'ARM32': [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9],
        'AArch64': [UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15]
    }
    # Return a tuple of all register value for the given arch
    return tuple(mu.reg_read(reg) for reg in reg_map.get(arch, []))

```

And then we just need to read the register value we need from all register returned and format it as required in the challenge

```python
    reg_out = emulate(code, arch)
    
    payload = ""

    if arch in ["x86", "x64"]:
        reg_names = ["ax", "bx", "cx", "dx"]
    elif arch == "ARM32":
        reg_names = [f"r{i}" for i in range(10)]
    elif arch == "AArch64":
        reg_names = [f"x{i}" for i in range(8, 16)]

	# iterate over all registry values asked by the challenge and read their value of them in the returned tuple reg_out 
    for r in reg:
        for i, name in enumerate(reg_names):
            if name.encode() in r:
                payload += format(reg_out[i]) + ","
	# remove the last ',' as the challenge ask for reg1_val, reg2_val, reg3_val
    payload = payload[:-1]

	# Send the payload to the remote
    io.sendline(payload.encode())
```



And voilà, we iterate 15 times and get the flag :


## Final script :

```python
from pwn import *
from unicorn import *
from unicorn.x86_const import *
from unicorn.arm_const import *
from unicorn.arm64_const import *
from capstone import *
import binascii

def init_unicorn(arch):
    arch_dict = {
        'x86': (UC_ARCH_X86, UC_MODE_32),
        'x64': (UC_ARCH_X86, UC_MODE_64),
        'ARM32': (UC_ARCH_ARM, UC_MODE_ARM),
        'AArch64': (UC_ARCH_ARM64, UC_MODE_ARM)
    }
    if arch in arch_dict:
        return Uc(*arch_dict[arch])
    else:
        raise ValueError(f"Architecture not implemented: {arch}")


def read_registers(mu, arch):
    reg_map = {
        'x86': [UC_X86_REG_EAX, UC_X86_REG_EBX, UC_X86_REG_ECX, UC_X86_REG_EDX],
        'x64': [UC_X86_REG_RAX, UC_X86_REG_RBX, UC_X86_REG_RCX, UC_X86_REG_RDX],
        'ARM32': [UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2, UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5, UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8, UC_ARM_REG_R9],
        'AArch64': [UC_ARM64_REG_X8, UC_ARM64_REG_X9, UC_ARM64_REG_X10, UC_ARM64_REG_X11, UC_ARM64_REG_X12, UC_ARM64_REG_X13, UC_ARM64_REG_X14, UC_ARM64_REG_X15]
    }
    return tuple(mu.reg_read(reg) for reg in reg_map.get(arch, []))

def format(value):
    if value == 0:
        return "0x00"
    elif value <= 0xff:
        return f"0x{value:02x}"
    elif value <= 0xfff:
        return f"0x{value:03x}"
    else:
        return f"0x{value:04x}"

def emulate(code, arch):
    ADDRESS = 0x10000

    mu = init_unicorn(arch)
    mu.mem_map(ADDRESS, 4 * 1024 * 1024)
    mu.mem_write(ADDRESS, shellcode)

    mu.emu_start(ADDRESS, ADDRESS + len(code))

    return read_registers(mu, arch)

io = remote("challenge.ctf.bzh", 31986)

for i in range(15):
    print(f"Etape : [{i + 1}/15]")
    io.recvuntil(b"registres ")
    reg = io.recvuntil(b"apr").split(b"apr")[0].strip()
    print(reg)
    reg = reg.split(b',')
    io.recvuntil(b"code assembleur ")

    arch = io.recvuntil(b"suivant :").split(b" ")[0].strip().decode()
    bc = io.recvuntil(b"\n").strip()

    code = binascii.unhexlify(bc.replace(b'\\x', b''))
    reg_out = emulate(code, arch)

    payload = ""

    if arch in ["x86", "x64"]:
        reg_names = ["ax", "bx", "cx", "dx"]
    elif arch == "ARM32":
        reg_names = [f"r{i}" for i in range(10)]
    elif arch == "AArch64":
        reg_names = [f"x{i}" for i in range(8, 16)]

    for r in reg:
        for i, name in enumerate(reg_names):
            if name.encode() in r:
                payload += format(reg_out[i]) + ","

    payload = payload[:-1]
    print(payload)
    io.sendline(payload.encode())

print(io.recvline().decode())
```
