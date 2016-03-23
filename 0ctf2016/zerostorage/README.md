- Thanks the senior driver @brieflyX ;-)

1.If we merge the same chunks,we will get an UAF velnerability

2.Read the free chunk we will get libc_base and heap addr

3.(The challenge's key point:hijacking global_max_fast) overwite the unsorted chunks BK in &global_max_fast-0x10,then a malloc called to get this unsorted chunk,global_max_fast will be overwrited in &unsorted_bin(0x7fffxxxxxx) 

4.It's amazing that every chunks will be treated as fast chunks now

5.Free some chunks (though it's size in range(128,4096),but glibc will treat it as fast chunk)

6.Use the UAF vulnerability to overwrite this chunk's FD in .bss

7.After two malloc(s) are called,we will get a fake chunk in .bss

8.Read the chunk then the rand_key will be leaked

9.Overwite Node->ptr in (rand_key XOR free_hook)

10.Edit this chunk and overwite the free_hook in libc's magic_gadget(onegadget to spawn a shell^.^)

11.Trigger delete() and enjoy your shell ;-)
