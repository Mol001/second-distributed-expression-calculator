# second-distributed-expression-calculator
Для запуска необходимо скопировать все файлы на устройство

Возможно понадобится установить через go get следующее:

"github.com/form3tech-oss/jwt-go"
"golang.org/x/exp/slices"
"database/sql"
_ "github.com/mattn/go-sqlite3"

Для работы с сервером необходимо:

1/Запустить main1.go, убедившись в том, что все файлы скачаны.

2/Вбить в поисковую строку localhost:8082/api/v1/register?login=userLogin&password=userPassword, получить в ответ OK в случае упеха, после чего вбить localhost:8082/api/v1/login?login=userLogin&password=userPassword, получить в ответ jwt-токен в случае упеха (userLogin и userPassword - пример).

3/Далее следует вбить localhost:8082/ для перемешения на главную страницу. Далее для перемещение между страницами доступно меню в верху страницы, если не пройти вход на страницах будет отображаться сообщение "Invalid token".

Для смены "аккаунта", необходимо опять пройти пункт 2 с другими значениями login и password.

Для каждого аккаунта отображаются его собственные запросы. При отправке выражения, которое уже отправленно другим пользователем, оно будет отображенно без повторного вычисления.

Все базы создадутся при первом включении.

При перезапуске, невычисленные выражения продолжат своё выполнение.

Все адреса(предпологается доступ к ним по меню):

http://localhost:8082/ | По данному адресу открывается страница с меню, полем для ввода данный и кнопкой отправки выражения. При оправке выражения, открывается страница /calculate, где отображается статус выражения(при повторной отправке выражения, будет отображён стату 200 по условию) http://localhost:8082/storage | По данному адресу открывается страница со списоком принятых на обработку и уже обработанных выражений http://localhost:8082/calculate | Адрес обрабатываемый кнопкой на главной странице, где отображается статус выражения http://localhost:8082/operations | По данному адресу открывается страница с окнами для изменения времени выполнения каждой операции, для изменения нажимается кнопка http://localhost:8082/agents | По данному адресу открывается страница с серверами и их статусами

По умолчанию в коде работают 2 агента.

тг для связи по вопросам запуска и т.д. https://t.me/molll01
