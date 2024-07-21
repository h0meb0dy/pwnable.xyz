# [pwnable.xyz] misalignment

> Try not using a debugger for this one.

## Analysis

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  __int64 s[20]; // [rsp+10h] [rbp-A0h] BYREF

  s[19] = __readfsqword(0x28u);
  setup(argc, argv, envp);
  memset(s, 0, 0x98uLL);
  *(__int64 *)((char *)&s[1] + 7) = 0xDEADBEEFLL;
  while ( (unsigned int)_isoc99_scanf("%ld %ld %ld", &s[4], &s[5], &s[6]) == 3 && s[6] <= 9 && s[6] >= -7 )
  {
    s[s[6] + 7] = s[4] + s[5];
    printf("Result: %ld\n", s[s[6] + 7]);
  }
  if ( *(__int64 *)((char *)&s[1] + 7) == 0xB000000B5LL )
    win();
  return 0;
}
```

`&s[1] + 7`에 있는 값이 `0xb000000b5`이면 플래그를 획득할 수 있다. 8바이트 단위로 생각하면, `s[1]`은 `0xb5??????????????`이 되어야 하고, `s[2]`는 `0x????????0b000000`이 되어야 한다.

## Exploit

처음 입력에서 `s[4]`에 `0xb500000000000000`(`-5404319552844595200`), `s[5]`에 `0`, `s[6]`에 `-6`을 입력하면 `s[-6 + 7] = 0xb500000000000000 + 0`이 된다.

두 번째 입력에서 `s[4]`에 `0xb000000`(`184549376`), `s[5]`에 `0`, `s[6]`에 `-5`를 입력하면 `s[-5 + 7] = 0xb000000 + 0`이 된다.

여기까지 하고 메모리의 상태를 보면 다음과 같다.

![image](https://github.com/user-attachments/assets/644ecd48-704b-4262-959e-86ce9b810bd3)

`&s[1] + 7`에 원하는 대로 `0xb000000b5`가 들어가있는 것을 확인할 수 있다. 다음에는 문자를 입력해서 `scanf()`의 반환값이 3이 아니도록 하여 반복문을 빠져나오면, 조건문을 통과하여 `win()`이 실행된다.

![image](https://github.com/user-attachments/assets/5621d19f-6a43-43f4-8d6b-a6b3cbcd1128)
