# [pwnable.xyz] add

> We did some subtraction, now let's do some addition.

## Analysis

![image](https://github.com/user-attachments/assets/f5eddf7b-e9b4-48b1-8df1-a9aeadf3abea)

스택에서 임의의 위치에 임의의 8바이트 값을 넣을 수 있다.

## Exploit

PIE가 비활성화되어 있기 때문에 `main()`의 return address에 `win()`의 주소를 넣고 return하면 플래그를 획득할 수 있다.

`while (1)`을 탈출하기 위해서는 `scanf()`의 return value가 3이 아니어야 한다. 이것은 `scanf()`에 `%ld`로 받을 수 없는 문자를 입력하면 된다.

![image](https://github.com/user-attachments/assets/52374ba1-e8e5-4095-bfef-8797b5290833)
