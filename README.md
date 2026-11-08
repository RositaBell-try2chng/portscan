Пакет для сканирования портов
Тестовое на GO

1. Как использовать пакет
    Создаете сканер с помощью конструктора NewScanner(concurrency uint16, timeout time.Duration) (*Scanner, error)
    Проверяете на ошибку.
    Создаете объект context.Context
    Запускаете (s *Scanner)Scan(ctx context.Context, hosts []string, ports []uint16) ([]Result, error)
    Хосты - слайс строк.
    Порты можно задать вручную или использовать Range(принимает 2 uint16) для простого диапозона и FlexRange(принимает любой набор в любой последовательности из uint16 и []uint16).

    Простой пример:
    func main() {
        ctx, cancel := context.WithTimeout(
            context.Background(),
            30*time.Second,
        )
        defer cancel()

        sc, err := portscan.NewScanner(
            10,
            500 * time.Millisecond,
        )
        
        if err != nil {
            fmt.Println(err)
            return
        }

        hosts := []string {
            "127.0.0.1",
            "localhost",
            "google.com",
            "192.168.1.1",
            "invalid-domain.examlpe",
        }

        ports := []uint16{
            80,
            443,
            8080,
            3306,
        }
        
        results, err := sc.Scan(ctx, hosts, portscan.FlexRange(ports, []uint16{21, 2121, 21212}))
        if err != nil {
            fmt.Println(err)
        }

        for _, res := range results {
            fmt.Println(res)
        }
    }

2. Как устроен публичный API
    Создание сканера только через функцию NewScanner(uint16, time.Duration) (*Scanner, error)
    аргументы: 1 - количество одновременных подключений(>0), 2 - таймаут на подключение(>0)
    возвращает сканнер или ошибку в случае некорректных аргументов.

    Для запуска сканирования используем 
    (s *Scanner)Scan(ctx context.Context, hosts []string, ports []uint16) ([]Result, error)
    Возвращает то что смог/успел обработать сканер в слайсе с результатами и/или ошибку если нечего проверять или поймали отмену через контекст

    type Result struct {
        Host string
        IP net.IP
        Port uint16
        State State
        Duration time.Duration
        Err error
    }

    Задавать порты можно через функции Range(st, en uint16) []uint16 и FlexRange(args ...any) []uint16. В случае некорректного ввода возвращают nil или пустой слайс.

    Возможные результаты проверки в Result.State
    "open" - успешно
	"closed" - отклонено
	"timeout" - таймаут
	"unreachable" - нет подключения к интернету или к серверу
	"dns failed" - не получилось зарезолвить хостнейм
	"canceled" - поймали отмену через контекст
	"permission denied" - недостаточно прав
	"error" - другая ошибка

    Контракты
    Повторы хостов дедуплицируются по паре (host, ip).
    Некорректные адреса по типу 256.1.1.1 возвращаются, как ошибка резолва.
    Пустые хосты игнорируются.

    Порт 0 приводит к возвращению ошибки.
    Дублирующие порты удаляются.
    Функции принимают uint16 в качестве порта, поэтому значение больше 65535 не выразить.
