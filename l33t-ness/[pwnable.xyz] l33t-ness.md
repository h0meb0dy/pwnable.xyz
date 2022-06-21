# [pwnable.xyz] l33t-ness

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Some more basic math
>
> Release: [l33t-ness.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8946809/l33t-ness.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174743832-d33f478f-3a0b-4b50-978c-e8e9feaa3307.png)

## Analysis

### `win()`

```c
int win()
{
  return system("cat /flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### `main()`

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  setup(argc, argv, envp);
  puts("The l33t-ness level.");
  if ( (unsigned __int8)round_1() && (unsigned __int8)round_2() && (unsigned __int8)round_3() )
    win();
  return 0;
}
```

`round_1()`, `round_2()`, `round_3()`을 차례대로 실행한다. 세 함수의 반환값이 모두 0이 아니면 `win()`을 실행한다.

### `round_1()`

```c
_BOOL8 round_1()
{
  int num1; // [rsp+8h] [rbp-38h]
  int num2; // [rsp+Ch] [rbp-34h]
  char s[40]; // [rsp+10h] [rbp-30h] BYREF
  unsigned __int64 v4; // [rsp+38h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  puts("=== 1eet ===");
  memset(s, 0, 0x20uLL);
  printf("x: ");
  read(0, s, 0x10uLL);
  printf("y: ");
  read(0, &s[16], 0x10uLL);
  if ( strchr(s, '-') || strchr(&s[0x10], '-') )
    return 0LL;
  num1 = atoi(s);
  num2 = atoi(&s[16]);
  return num1 <= 1336 && num2 <= 1336 && num1 - num2 == 1337;
}
```

`num1`과 `num2`를 입력받는다. 두 수는 모두 `1336`보다 작거나 같아야 하고, `num1`에서 `num2`를 뺀 결과는 `1337`이어야 한다. 입력에 `'-'`가 있는지 `strchr()`로 검사하기 때문에 음수는 입력할 수 없다.

`num1`이 `1336`이고 `num2`가 `-1`이면 되는데, 음수는 입력할 수 없기 때문에 대신 `0xffffffff`(`4294967295`)를 입력하면 된다.

### `round_2()`

```c
_BOOL8 round_2()
{
  int num1; // [rsp+0h] [rbp-10h] BYREF
  int num2; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v3; // [rsp+8h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("=== t00leet ===");
  num1 = 0;
  num2 = 0;
  _isoc99_scanf("%d %d", &num1, &num2);
  return num1 > 1 && num2 > 1337 && num1 * num2 == 1337;
}
```

`num1`과 `num2`를 입력받는다. `num1`은 1보다 커야 하고, `num2`는 1337보다 커야 하며, `num1`과 `num2`를 곱한 결과가 `1337`이어야 한다.

`num1 * num2`의 결과를 `1337`과 비교하는 부분의 어셈블리 코드를 보면 다음과 같다.

```assembly
mov     edx, [rbp+num1]
mov     eax, [rbp+num2]
imul    eax, edx
cmp     eax, 539h
jnz     short loc_C8F
```

두 수를 곱한 결과를 `eax`에 넣고 `0x539`과 비교한다. 따라서 곱한 결과가 4바이트를 넘어가면 오버플로우가 발생하여 위쪽은 잘리고 아래 4바이트만 의미가 있다.

곱했을 때 `0x100000539`, 또는 `0x200000539`, ... 가 되는 두 수를 `num1`과 `num2`에 넣으면 된다.

![image](https://user-images.githubusercontent.com/104156058/174748653-3ede91d2-4b76-4949-a95f-0a97f214b6fe.png)

`num1`에 `3`, `num2`에 `0x55555713`(`1431656211`)을 넣으면 된다.

### `round_3()`

```c
_BOOL8 round_3()
{
  int i; // [rsp+0h] [rbp-30h]
  int num[5]; // [rsp+10h] [rbp-20h] BYREF
  unsigned __int64 v3; // [rsp+28h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  puts("=== 3leet ===");
  memset(num, 0, sizeof(num));
  _isoc99_scanf("%d %d %d %d %d", num, &num[1], &num[2], &num[3], &num[4]);
  for ( i = 1; i <= 4; ++i )
  {
    if ( num[i] < num[i - 1] )
      return 0LL;
  }
  return num[3] + num[2] + num[1] + num[0] + num[4] == num[3] * num[2] * num[1] * num[0] * num[4];
}
```

5개의 수를 입력받는다. `num[0]`부터 `num[4]`까지 각각의 수들은 앞의 수보다 크거나 같아야 하고, 다섯 개의 수를 더한 결과와 곱한 결과가 같아야 한다.

`num[0]`부터 `num[4]`까지에 모두 0을 넣으면 더한 결과와 곱한 결과가 모두 0이 되어 조건을 만족한다.

## Exploit

```
$ nc svc.pwnable.xyz 30008
The l33t-ness level.
=== 1eet ===
x: 1336
y: 4294967295
=== t00leet ===
3 1431656211
=== 3leet ===
0 0 0 0 0
FLAG{1eet_t00leet_3leet_4z}
```