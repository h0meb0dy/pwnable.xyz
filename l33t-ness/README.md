# [pwnable.xyz] l33t-ness

> Some more basic math

## Analysis

### round_1

![image](https://github.com/user-attachments/assets/9318b6e3-ccff-4601-a3db-0bf84dbf9753)

`x`에는 1336, `y`에는 `-1`을 넣으면 되는데, 음수를 입력할 수 없기 때문에 `-1` 대신 `0xffffffff`를 입력하면 된다.

### round_2

![image](https://github.com/user-attachments/assets/de140aa4-7494-4885-8762-5a2bd2e12556)

수학적으로는 조건을 만족하는 `x`와 `y`를 찾을 수 없지만,

![image](https://github.com/user-attachments/assets/ef881110-ef03-4816-949b-c8f0d6081023)

`x * y`를 1337과 비교하는 것은 4바이트 값들 간의 연산이기 때문에 `x * y`의 하위 4바이트만 1337이면 된다.

![image](https://github.com/user-attachments/assets/cf2907ca-9679-4352-be65-58181f4d4c9e)

### round_3

![image](https://github.com/user-attachments/assets/9ad78957-5cc9-4375-b6bd-906ee015fd12)

입력한 수들은 모두 앞의 수보다 작을 수 없고, 다섯 개의 수들을 모두 더한 결과와 모두 곱한 결과가 같아야 한다. 모두 0을 넣으면 통과할 수 있다.

## Exploit

![image](https://github.com/user-attachments/assets/6a95065b-2286-4bbf-b9ee-c1e702e50d12)
