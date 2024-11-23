# Firewall


Программа, позволяющая фильтровать пакеты, передаваемые между клиентами.


---


## Запуск


Для запуска программы введите
```
python3 filter.py rule --queue-num
```
rule - путь до файла, содержащий правила фильтрации.


## Правила
Формат файла с правилам:
```
action={0,1} DNS QR={0,1} name=regx type=num class=num len=num data=regx

__Пример:__
```
DNS QR=0 name=ya.ru
```

