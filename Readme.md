# Firewall

Программа, позволяющаяя фильтровать пакеты, передаваемые между клиентами.

---

## Запуск

Для запуска программы введите
```
python3 filter.py rule interface1 interface2
```
rule - путь до файла, содержащий правила фильтрации
interface1, interface2 - имена интерфейсов, которые будет прослушивать фильтр.

## Правила
Формат файла с правилам:
```
{
    type: [black, white]  
    rules: 
    {
        {
            prot: [udp, tcp, icmp]
            srcIP: xxx.xxx.xxx.xxx
            dstIP: xxx.xxx.xxx.xxx
            srcPort: num
            dstPort: num
        },
        ...
    }
}
```

__Пример:__
```
{
    type: black, 
    rules: 
    {
        {
            srcIP: 192.168.0.1,
            dstIP: 123.123.123.123
            prot: udp
            dstPort: 3000
        },
        {
            prot: icmp
        },
        {
            prot: tcp
            dstPort: 200
        },
        {
            prot: tcp
            dstPort: 201
        }
    }
}
```