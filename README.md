#Система аутентификации
---
###Простой пример системы аутентификации, в которой присутствует проверка логина и пароля (в хэшированном виде), отправка cookies и их подпись.
#Запуск приложения
---
###Для запуска FastAPI используется веб-сервер uvicorn. Команда для запуска выглядит так:
```
uvicorn main:app --reload 
```
###Ее необходимо запускать в командной строке, обязательно находясь в корневой директории проекта.