# [pwnable.xyz] xor

> What can you access and what are you going to write?

## Bug

![image](https://github.com/user-attachments/assets/91cf8cc6-1b40-4fd8-829d-27c2bb2da1f3)

`v6`에 음수가 들어갈 수 있어서 `result`보다 낮은 임의의 주소에 임의의 8바이트 값을 쓸 수 있다.

## Exploit

메모리 맵을 보면 코드 영역에 `w` 권한이 있는 것을 확인할 수 있다. 즉, runtime에 임의의 코드를 수정할 수 있다. `main()`에서 `exit()`을 호출하는 부분의 코드를 수정해서 `win()`이 대신 호출되도록 하고, `scanf()`에 문자를 입력해서 반복문을 빠져나오면 플래그를 획득할 수 있다.

![image](https://github.com/user-attachments/assets/936dc807-928e-444a-99de-2ae7d537cebc)

`main+148`부터 5바이트가 `exit()`을 호출하는 코드에 해당한다.

![image](https://github.com/user-attachments/assets/0c9665ce-c85a-4d4d-bdb8-a583e9fc2d42)

기계어로는 `e8 63 fd ff ff`이다. `e8`은 `call`에 해당하고, 뒤의 4바이트는 호출할 함수의 주소를 나타낸다. 이 주소는 상대 주소로, 다음에 실행될 명령어의 주소의 offset(`0xacd`)에 상대 주소(`0xfffffd63`)를 더하면 호출할 함수의 주소의 offset(`0x830`)이 된다.

`win()`의 offset은 `0xa21`이다. 이 부분의 코드를 `e8 54 ff ff ff`로 바꾸면, `0xacd + 0xffffff54 == 0xa21`이 되어 `win()`을 호출하는 코드가 된다.

결론적으로, `main+148`의 8바이트에 `0x458b48ffffff54e8`을 넣으면 플래그를 획득할 수 있다. `v6`에는 `result`부터 `main+148`까지의 거리를 계산해서 `-262887`을 입력하고, `v4`에는 `1`, `v5`에는 `0x458b48ffffff54e9`(`5011179274728592617`)를 입력하면 된다.

![image](https://github.com/user-attachments/assets/c3e77516-57e8-452d-8155-fd51bfd5a53f)
