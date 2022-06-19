# [pwnable.xyz] xor

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> What can you access and what are you going to write?
>
> Release: [xor.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8934846/xor.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/174468078-20e7af87-f565-4dff-b693-8d3fc7cd701a.png)

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
  while ( 1 )
  {
    num3 = 0LL;
    printf(intro, argv);
    v3 = _isoc99_scanf("%ld %ld %ld", &num1, &num2, &num3);
    if ( !num1 || !num2 || !num3 || num3 > 9 || v3 != 3 )
      break;
    result[num3] = num2 ^ num1;
    argv = (const char **)result[num3];
    printf("Result: %ld\n", argv);
  }
  exit(1);
```

세 개의 정수를 입력받는다. 0이 있으면 안 되고, `num3`은 `9` 이하여야 한다. 이 조건을 통과하면 `num1`과 `num2`를 xor한 결과를 `result[num3]`에 넣는다.

## Exploit

`num3`은 `9` 이하여야 하지만 아래로는 제한이 없기 때문에 음수를 입력할 수 있다. 따라서 OOB 취약점이 발생하여, `result`보다 낮은 주소에는 어디든지 원하는 값을 쓸 수 있다.

메모리 맵을 보면 코드 영역에 `w` 권한이 있는 것을 확인할 수 있다. 즉, 프로그램이 실행되는 동안 임의의 코드를 수정할 수 있다. `main()`에서 `exit()`을 호출하는 부분의 코드를 수정해서 `win()`이 대신 호출되도록 하고, `scanf()`에 문자를 입력해서 반복문을 빠져나오면 플래그를 획득할 수 있다.

![image](https://user-images.githubusercontent.com/104156058/174470255-c8f19835-b80c-473c-9ece-300ed75fe7ad.png)

`main+148`부터 5바이트가 `exit()`을 호출하는 코드에 해당한다.

![image](https://user-images.githubusercontent.com/104156058/174470328-d140849c-5850-4688-b436-8c4beec4004a.png)

기계어로는 `e8 63 fd ff ff`이다. `e8`은 `call`에 해당하고, 뒤의 4바이트는 호출할 함수의 주소를 나타낸다. 이 주소는 상대 주소로, 다음에 실행될 명령어의 주소의 오프셋(`0xacd`)에 상대 주소(`0xfffffd63`)를 더하면 호출할 함수의 주소의 오프셋(`0x830`)이 된다.

`win()`의 오프셋은 `0xa21`이다. 이 부분의 코드를 `e8 54 ff ff ff`로 바꾸면, `0xacd + 0xffffff54 == 0xa21`이 되어 `win()`을 호출하는 코드가 된다.

결론적으로, `main+148`의 8바이트에 `0x458b48ffffff54e8`을 넣으면 플래그를 획득할 수 있다. `num3`에는 `result`부터 `main+148`까지의 거리를 계산해서 `-262887`을 입력하고, `num1`에는 `1`, `num2`에는 `0x458b48ffffff54e9`(`5011179274728592617`)를 입력하면 된다.

```
$ nc svc.pwnable.xyz 30029
The Poopolator
> 💩   1 5011179274728592617 -262887
Result: 5011179274728592616
> 💩   a
FLAG{how_did_text_happen_to_be_rwx}Result: 5011179274728592616
```