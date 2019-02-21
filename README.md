### Извлечение закрытого ключа из контейнера КриптоПро

##### TODO

- [ ] Поддержка 2012го ГОСТа

#### ExtractPkey - первый способ

Позволяет извлечь закрытый ключ из любого контейнера. Требуется установленный КриптоПро CSP и установленный сертификат. Закрытый ключ должен быть экспортируемым.

Использование:

- `extractpkey -t "‎db 89 1d 0f f0 85 0f 09 b5 4d c5 1a d0 eb af fd 35 57 4d 4a"` - указывается отпечаток (thumbprint) сертификата.

#### ExtractPkey2 - второй способ

Извлечение закрытого ключа из файлового контейнера или из реестра. Не требует наличия установленного КриптоПро CSP. Реализует [этот](https://habr.com/ru/post/275039/) алгоритм.

Примеры:

- `extractpkey -f g:\hcskberm.000 -p 12345678`
- `extractpkey -f g:\hcskberm.000 -p 12345678 --cert`
- `extractpkey -r le-dfa0f60b-4b16-49af-a5fe-af7acf4e6fed -p 12345678`
