# Hitcon_ftp
This challenge is super hard and I learnt a lot from this too

## Bugs
There are 3 main bugs:
- Type confusion --> oob check
- Bof
- %s exploit

## Exploit
All bugs are explained inside IDA, I'm too lazy to write up

I'm so sorry to my future self

solve.py and back_up.py are correct script but the server doesn't give flag sometimes

This may be because based on how packets are send over the netwok. Result in some packets aren't received as expected and lead to unexpected behavior

My exploit is simple, overwrite saved rip to rop chain to mprotect heap chunk and execute shellcode that stores flag then call **send_to** function inside binary to send back to user

Byeee :)

**bonus**: poc2.py is a script that I attempt to rewrite to send and receive packet using remote with **typ="udp"** so that I can send and receive packets like normal tcp connection. 

Yea this is a UDP based challenges :))

**bonus 2**: dockerfile and compose are created by me and gpt, it is just for patched binary