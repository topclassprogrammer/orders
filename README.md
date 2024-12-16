# Дипломный проект профессии «Python-разработчик: с нуля до middle» на тему: "Backend-приложение для автоматизации закупок"

Backend-приложение написано на языке Python 3.12 и фреймворке Django.  

## Описание
Пользователи регистрируются в приложении и могут осуществлять вход/выход из аккаунта. Им по умолчанию назначается роль клиента. Если пользователь добавляет магазин, то ему назначается роль магазина и он может добавлять товары с характеристиками и фотографиями в общий каталог.
Остальные пользователи приложения могут добавлять товары в свою корзину от разных магазинов в количестве не превышающем количество имеющихся товаров в наличии у магазина. После добавления товаров в корзину пользователь может оформить заказ на основе имеющихся товаров в корзине, указав адрес доставки. После оформления заказа клиент и администратор(ы) приложения получают соответствующие автоматические уведомления о новом заказе на свои email.  
При первом запуске приложения происходит автоматическая загрузка первоначальных фикстур в БД: перечень ролей и непосредственно сам пользователь с ролью администратора. Для получения его учетных данных, см. файл .env.example.  
Все взаимодействие с приложением происходит исключительно через API запросы.  


## Как развернуть приложение

- склонировать репозиторий: ```git clone https://github.com/topclassprogrammer/orders.git```
- перейти в папку проекта: ```cd ./orders/orders```
- переименовать файл с переменными окружениями: ```mv .env.example .env```. В файле .env достаточно заменить только переменную ADMIN_EMAIL на свой собственный email для получения уведомлений о сформированных заказов клиентами.
- перейти на уровень вверх: ```cd ..```
- запустить контейнер: ```docker-compose up -d```
- готово! Отправлять HTTP-запросы к API приложения рекомендуется через Postman, используя готовую [конфигурацию](https://documenter.getpostman.com/view/31039387/2sAYBYgqgS#b7a1c559-9a44-4c16-9326-5b53094c8551). 

---

Ниже перечисляются действия, которые может совершать пользователь через API, используя базовую часть URL: http://127.0.0.1:8000/api/v1  


## Пользователи

### Регистрация пользователя
Endpoint: <u>/user/</u>  
Метод: <u>POST</u>    
Тело запроса:  
**first_name** - имя  
**last_name** - фамилия  
**username** - имя пользователя
**password** - пароль  
**email** - электронная почта
**phone** - телефон  

Если регистрация проходит успешно, то пользователю назначается роль клиента и на указанный email приходит письмо с токеном активации аккаунта.

### Активация аккаунта
Endpoint: <u>/user/activate/</u>  
Метод: <u>POST</u>   
Тело запроса:  
**key** - токен активации, отправленный на email пользователя при успешной регистрации аккаунта

Если пользователь не активирует аккаунт, то он не сможет в него войти.

### Вход в аккаунт
Endpoint: <u>/user/log-in/</u>  
Метод: <u>POST</u>   
Тело запроса:  
**username** - имя пользователя  
**password** - пароль

Пользователь может входить в аккаунт только, если он его активировал.  
Если имя пользователя и пароль совпадают, то пользователю выдается токен аутентификации.

<u>Во всех последующих запросов к API пользователь должен предоставлять в заголовке HTTP-запроса выданный токен аутентификации в следующем формате:</u>   
<b>Authorization: 'Token xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx'</b>

### Выход из аккаунта
Endpoint: <u>/user/log-out/</u>  
Метод: <u>POST</u>   
Тело запроса: отсутствует

### Запросить сброс пароля
Endpoint: <u>/user/request-new-password/</u>  
Метод: <u>POST</u>  
Тело запроса: отсутствует

Пользователю на указанный email при регистрации аккаунта отправляется токен сброса пароля.

### Изменение пароля
Endpoint: <u>/user/set-new-password/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**key** - токен сброса пароля, отправленный на указанный email при регистрации аккаунта   
**password** - новый пароль

Текущий и новый пароли пользователя не должны совпадать.

### Получение списка пользователей
Endpoint: <u>/user/</u>    
Метод: <u>GET</u>  

Только пользователи с ролью администратора могут получить список всех зарегистрированных пользователей в приложении, кроме их паролей.

### Получение пользователя
Endpoint: <u>/user/1/</u>    
Метод: <u>GET</u>  

Любой зарегистрированный пользователь в приложении может получить все данные о другом пользователе, кроме его пароля.

### Изменение данных в аккаунте
Endpoint: <u>/user/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**first_name** - имя  
**last_name** - фамилия  
**username** - имя пользователя(должно быть уникальным)  
**password** - пароль  
**email** - электронная почта(должна быть уникальной)  
**phone** - телефон  

Любой пользователь в приложении может изменять данные своего аккаунта.

### Удаление аккаунта
Endpoint: <u>/user/1/</u>  
Метод: <u>DELETE</u>  

Любой пользователь в приложении может удалить свой аккаунт.

---

## Роли

<u>Только для пользователей с ролью администратора</u>

### Создание роли
Endpoint: <u>/role/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**name** - название роли

### Получение списка ролей
Endpoint: <u>/role/</u>    
Метод: <u>GET</u>  

### Получение роли
Endpoint: <u>/role/1/</u>    
Метод: <u>GET</u>  

### Изменение роли
Endpoint: <u>/role/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**name** - название роли

### Удаление роли
Endpoint: <u>/role/1/</u>  
Метод: <u>DELETE</u>  
Тело запроса:  
**name** - название роли

---

## Магазины

### Создание магазина
Endpoint: <u>/shop/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**name** - название магазина  
**url** - URL магазина, начинающийся с http://, https:// или www.

После успешного создания магазина пользователю назначается роль магазина. Он не может создавать более одного магазина. По умолчанию магазину устанавливается флаг приема заказов в значение True.

### Прием заказов
Endpoint: <u>/shop/switch-accept-orders/</u>  
Метод: <u>POST</u>  
Тело запроса: отсутствует

Владелец магазина может включать и выключать прием заказов.

### Получение списка магазинов
Endpoint: <u>/shop/</u>  
Метод: <u>GET</u>  

### Получение магазина
Endpoint: <u>/shop/1/</u>    
Метод: <u>GET</u>  

### Получение заказов магазинов
Endpoint: <u>/shop/active-orders/</u>    
Метод: <u>GET</u>  

Пользователи с ролью клиента не могут получать список активных заказов магазина.  
Пользователи с ролью магазина могут получать список активных заказов своего магазина.  
Пользователи с ролью администратора могут получать список активных заказов всех магазинов.  
Примечание: под активными заказами понимаются заказы, находящиеся в состояниях не 'In cart', и не 'Canceled'.  

### Изменение данных магазина
Endpoint: <u>/shop/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**name** - название магазина  
**url** - URL магазина, начинающийся с http://, https:// или www.

Владелец магазина может изменить данные своего магазина.

### Удаление магазина
Endpoint: <u>/shop/1/</u>  
Метод: <u>DELETE</u>  

Владелец магазина может удалить свой магазин.

---

## Адресы доставки

### Создание адреса
Endpoint: <u>/address/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**country** - страна  
**region** - область/край/провинция/республика/штат  
**city** - город  
**street** - улица  
**house** - дом  
**apartment** - квартира  

### Получение списка адресов
Endpoint: <u>/address/</u>    
Метод: <u>GET</u>  

В список адресов попадают те адреса, которые создал пользователь. Если у пользователя установлена роль администратора, то он получит список адресов всех пользователей.

### Получение адреса
Endpoint: <u>/address/1/</u>    
Метод: <u>GET</u>  

Владелец адреса может получить только свой адрес.

### Изменение адреса
Endpoint: <u>/address/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**country** - страна  
**region** - область/край/провинция/республика/штат  
**city** - город  
**street** - улица  
**house** - дом  
**apartment** - квартира  

Владелец адреса может изменить свой адрес.

### Удаление адреса
Endpoint: <u>/address/1/</u>  
Метод: <u>DELETE</u>  

Владелец адреса может удалить свой адрес.

---

## Бренды

### Создание бренда
Endpoint: <u>/brand/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**name** - название бренда

Пользователи с ролью магазина могут создавать бренд. 

### Получение списка брендов
Endpoint: <u>/brand/</u>  
Метод: <u>GET</u>  

### Получение бренда
Endpoint: <u>/brand/1/</u>  
Метод: <u>GET</u>  

### Изменение бренда
Endpoint: <u>/brand/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**name** - название бренда

Только пользователи с ролью администратора могут изменять бренды, т.к. один и тот же бренд может использоваться в множестве товаров разных магазинов. 

### Удаление бренда
Endpoint: <u>/brand/1/</u>  
Метод: <u>DELETE</u>  

Только пользователи с ролью администратора могут удалять бренды, т.к. один и тот же бренд может использоваться в множестве товаров разных магазинов.

---

## Модели

### Создание модели
Endpoint: <u>/model/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**name** - название модели  
**brand** - id бренда

Только пользователи с ролью магазина могут создавать модель. 

### Получение списка моделей
Endpoint: <u>/model/</u>  
Метод: <u>GET</u>  

### Получение модели
Endpoint: <u>/model/1/</u>  
Метод: <u>GET</u>  

### Изменение модели
Endpoint: <u>/model/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**name** - название модели  
**brand** - id бренда

Только пользователи с ролью администратора могут изменять модели, т.к. одна и та же модель может использоваться в множестве товаров разных магазинов.

### Удаление модели
Endpoint: <u>/model/1/</u>  
Метод: <u>DELETE</u>  

Только пользователи с ролью администратора могут удалять модели, т.к. одна и та же модель может использоваться в множестве товаров разных магазинов.

---

## Категории

### Создание категории
Endpoint: <u>/category/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**name** - название категории  

Пользователи с ролью магазина могут создавать категории. 

### Получение списка категорий
Endpoint: <u>/category/</u>  
Метод: <u>GET</u>  

### Получение категории
Endpoint: <u>/category/1/</u>  
Метод: <u>GET</u>  

### Изменение категории
Endpoint: <u>/category/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**name** - название категории

Только пользователи с ролью администратора могут изменять категории, т.к. одна и та же категория может использоваться в множестве товаров разных магазинов.

### Удаление категории
Endpoint: <u>/category/1/</u>  
Метод: <u>DELETE</u>  

Только пользователи с ролью администратора могут удалять категории, т.к. одна и та же категория может использоваться в множестве товаров разных магазинов.

---

## Товары

### Создание товара
Endpoint: <u>/item/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**brand** - id бренда  
**model** - id модели  
**category** - id категории  
**description** - описание товара  
**price** - цена товара  
**quantity** - количество товара  

Пользователи с ролью магазина могут добавлять товары в свой магазин. В один магазин невозможно добавить более одного товара, у которого совпадают бренд, модель и категория.

### Массовая загрузка товаров
Endpoint: <u>/item/bulk-upload/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**url** - URL до JSON-файла([образец](https://raw.githubusercontent.com/topclassprogrammer/orders/refs/heads/main/orders/bulk_upload_items.json))

### Получение списка товаров
Endpoint: <u>/item/</u>  
Метод: <u>GET</u>  

### Получение товара
Endpoint: <u>/item/1/</u> или <u>/item/apple-iphone-16-pro/</u>  
Метод: <u>GET</u>  

Товар можно получать не только по его id, но и по его слагу, который создается автоматически на основе имени бренда и имени модели.

### Изменение товара
Endpoint: <u>/item/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**brand** - id бренда  
**model** - id модели  
**category** - id категории  
**description** - описание товара  
**price** - цена товара  
**quantity** - количество товара  

Пользователи с ролью магазина могут изменять свои товары.  

### Добавить фотографию к товару
Endpoint: <u>/item/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**image** - фотография товара, имеющаяся на устройстве пользователя

Пользователи с ролью магазина могут к своим товарам добавлять фотографию.

### Удаление товара
Endpoint: <u>/item/1/</u>  
Метод: <u>DELETE</u>  

Пользователи с ролью магазина могут удалять свои товары.  

---

## Названия свойств товара

### Создание названия свойства товара
Endpoint: <u>/property-name/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**name** - название свойства товара

Пользователи с ролью магазина могут создавать свойства товара.  

### Получение списка названий свойств товара
Endpoint: <u>/property-name/</u>  
Метод: <u>GET</u>  

### Получение названия свойства товара
Endpoint: <u>/property-name/1/</u>  
Метод: <u>GET</u>  

### Изменение названия свойства товара
Endpoint: <u>/property-name/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**name** - название свойства товара

Только пользователи с ролью администратора могут изменять названия свойств товаров, т.к. одно и то же название свойства может использоваться в множестве товаров разных магазинов.

### Удаление имени свойства
Endpoint: <u>/property-name/1/</u>  
Метод: <u>DELETE</u>  

Только пользователи с ролью администратора могут удалять названия свойств товаров, т.к. одно и то же название свойства может использоваться в множестве товаров разных магазинов.

---

## Значения свойств товара

### Создание значения свойства товара
Endpoint: <u>/property-value/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**item** - id товара  
**property_name** - id названия свойства товара  
**value** - значение свойства товара  

Магазин, как владелец товара, может создавать значения свойства для своего товара.  

### Получение списка значений свойств товаров
Endpoint: <u>/property-value/</u>  
Метод: <u>GET</u>  

### Получение значения свойства товара
Endpoint: <u>/property-value/1/</u>  
Метод: <u>GET</u>  

### Изменение значения свойства товара
Endpoint: <u>/property-value/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**item** - id товара  
**property_name** - id названия свойства товара  
**value** - значение свойства товара

Магазин, как владелец товара, может изменять значения свойства для своего товара.  

### Удаление значения свойства товара
Endpoint: <u>/property-value/1/</u>  
Метод: <u>DELETE</u>  

Владелец товара может удалять значения свойства товара.  

---

## Корзина

### Добавить товар в корзину
Endpoint: <u>/order-item/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**item** - id товара  
**quantity** - количество добавляемого товара в корзину  

Если у клиента нет объекта заказа в состоянии 'In cart', то он создастся автоматически при добавлении первого товара в корзину. Все последующие добавляемые товары будут добавляться в один и тот же объект заказа клиента.

### Получение списка товаров в корзине
Endpoint: <u>/order-item/</u>  
Метод: <u>GET</u>  

Клиент может получить список товаров добавленных в свою корзину. Если у пользователя установлена роль администратора, то он получит список товаров в корзинах всех пользователей в приложении.

### Получение товара в корзине
Endpoint: <u>/order-item/1/</u>  
Метод: <u>GET</u>  

Клиент может получить товар добавленный в свою корзину. Если у пользователя установлена роль администратора, то он может получить товар в корзине любого пользователя в приложении.  

### Изменение товара в корзине
Endpoint: <u>/order-item/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**item** - id товара  
**quantity** - новое количество товара в корзине

Клиент может в своей корзине поменять один товар на другой, указав другой id товара, а также изменить его количество.  

### Удаление товара из корзины
Endpoint: <u>/order-item/1/</u>  
Метод: <u>DELETE</u>  

Клиент может удалить товар из своей корзины.  

---

## Заказ

### Оформить заказ
Endpoint: <u>/order/</u>  
Метод: <u>POST</u>  
Тело запроса:  
**address** - id адреса доставки

Заказ клиента изменяет свое состояние с 'In cart' на 'New'. Клиент и администратор получают соответствующие уведомления о новом заказе на свои email.

### Получение списка заказов
Endpoint: <u>/order/</u>  
Метод: <u>GET</u>  

Клиент может получить список своих оформленных заказов. Если у пользователя установлена роль администратора, то он получит список оформленных заказов всех пользователей в приложении.

### Получение информации о заказе
Endpoint: <u>/order/1/</u>  
Метод: <u>GET</u>  

Клиент может получить информацию о своем заказе. Если у пользователя установлена роль администратора, то он может получить информацию о заказе любого пользователя в приложении.

### Изменение состояния заказа
Endpoint: <u>/order/1/</u>  
Метод: <u>PATCH</u>  
Тело запроса:  
**state** - состояние заказа

Только пользователи с ролью администратора могут изменять состояние заказа.  

### Удаление заказа
Endpoint: <u>/order/1/</u>  
Метод: <u>DELETE</u>  

Только пользователи с ролью администратора могут удалять заказы.    

---

## Фотографии

### Получение списка фотографий
Endpoint: <u>/image/</u>  
Метод: <u>GET</u>

### Получение фотографии
Endpoint: <u>/image/1/</u>  
Метод: <u>GET</u>

### Удаление фотографии
Endpoint: <u>/image/1/</u>  
Метод: <u>DELETE</u>  

Фотографии могут удалять только их владельцы. Если у пользователя установлена роль администратора, то он может удалить фотографию, принадлежащую любому пользователю в приложении.
