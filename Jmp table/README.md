# [pwnable.xyz] Jmp table

> Should have let the compiler do it.

## Bug

![image](https://github.com/user-attachments/assets/8e855d5e-7564-4d54-9346-9a8485d6df55)

`idx`에 음수를 넣을 수 있다.

## Exploit

![image](https://github.com/user-attachments/assets/b3060f30-920e-4001-bf9a-1f94f4fadef6)

`size`에 플래그를 출력하는 `_()`의 주소를 쓰고 `idx`에 `-2`를 넣으면 플래그를 획득할 수 있다.

![image](https://github.com/user-attachments/assets/97fe58d1-1a5e-4619-9482-d761a2c64efc)
