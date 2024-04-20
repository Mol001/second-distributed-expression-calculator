package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/form3tech-oss/jwt-go"
	"golang.org/x/exp/slices"

	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

var jwtKey = []byte("qew") //  секретный ключ

var sesesion_token string
var sesesion_id = 0

func Middleware(next http.Handler) http.Handler {
	fmt.Println(sesesion_token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		tokenString := sesesion_token
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return jwtKey, nil
		})

		if err != nil {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			// Проверка на то, не истек ли срок действия токена
			if claims.VerifyExpiresAt(time.Now().Unix(), true) {
				next.ServeHTTP(w, r)
			} else {
				http.Error(w, "Token is expired", http.StatusUnauthorized)
				return
			}
		} else {
			http.Error(w, "Invalid token", http.StatusUnauthorized)
			return
		}
	})
}

func checkUserInDB(db *sql.DB, login, password string) (int, bool) {
	var userID int
	err := db.QueryRow("SELECT id FROM users WHERE Login=? AND Password=?", login, password).Scan(&userID)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, false
		}
		log.Println("Error querying database:", err)
		return 0, false
	}
	return userID, true
}

func addUserToDB(db *sql.DB, login, password string) error {
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM users WHERE Login=?)", login).Scan(&exists)
	if err != nil {
		return err
	}
	if exists {
		return fmt.Errorf("user with login %s already exists", login)
	}
	_, err = db.Exec("INSERT INTO users(Login, Password) VALUES(?, ?)", login, password)
	if err != nil {
		return err
	}

	return nil
}

// Функция для регистрации пользователя
func RegisterHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	login := r.URL.Query().Get("login")
	password := r.URL.Query().Get("password")

	// Проверка на то, что параметры запроса не пусты
	if login == "" || password == "" {
		http.Error(w, "Missing login or password", http.StatusBadRequest)
		return
	}

	db2, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db2.Close()
	err = addUserToDB(db2, login, password)
	if err != nil {
		http.Error(w, "Error saving user to DB", http.StatusInternalServerError)
		return
	}
	// В случае успеха отправляется ответ 200 OK
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("OK"))
}

// Функция для входа пользователя
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	login := r.URL.Query().Get("login")
	password := r.URL.Query().Get("password")

	// Проверка на то, что параметры запроса не пусты
	if login == "" || password == "" {
		http.Error(w, "Missing login or password", http.StatusBadRequest)
		return
	}

	db2, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db2.Close()
	user_personal_id, st := checkUserInDB(db2, login, password)
	if !st {
		http.Error(w, "Invalid login or password", http.StatusUnauthorized)
		return
	}
	// В случае успеха генерируется JWT токен
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"login": login,
		"exp":   time.Now().Add(time.Minute * 20).Unix(),
	})

	tokenString, err := token.SignedString(jwtKey)
	if err != nil {
		http.Error(w, "Error generating token", http.StatusInternalServerError)
		return
	}
	sesesion_token = tokenString
	sesesion_id = user_personal_id

	// Отправка JWT токена в ответе
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{
		"token": tokenString,
	})
}

var (
	additionSeconds       int
	subtractionSeconds    int
	multiplicationSeconds int
	divisionSeconds       int
)

var len_expr = make(map[string]int)

var db = make(map[string]string)
var agentConnected = make(map[string]string)

var agent_1 int = 5
var agent_2 int = 5
var perts_expr = []string{}
var db11 = make(map[int][]string)
var db22 = make(map[int][][]string)
var recvest_id = make(map[string]int)
var mutex sync.Mutex

// обработка базовых операций
func evaluateArithmeticExpression(expr string) int {
	parts := []string{}
	if strings.Contains(expr, "/") {
		timer := time.NewTimer(time.Second * time.Duration(divisionSeconds))
		<-timer.C
		parts = strings.Split(expr, "/")
		num1, _ := strconv.Atoi(parts[0])
		num2, _ := strconv.Atoi(parts[1])
		if num2 == 0 {
			return 0
		}
		return num1 / num2
	} else if strings.Contains(expr, "*") {
		timer := time.NewTimer(time.Second * time.Duration(multiplicationSeconds))
		<-timer.C
		parts = strings.Split(expr, "*")
		num1, _ := strconv.Atoi(parts[0])
		num2, _ := strconv.Atoi(parts[1])
		return num1 * num2
	} else if strings.Contains(expr, "-") {
		timer := time.NewTimer(time.Second * time.Duration(subtractionSeconds))
		<-timer.C
		parts = strings.Split(expr, "-")
		num1, _ := strconv.Atoi(parts[0])
		num2, _ := strconv.Atoi(parts[1])
		return num1 - num2
	} else if strings.Contains(expr, "+") {
		timer := time.NewTimer(time.Second * time.Duration(additionSeconds))
		<-timer.C
		parts = strings.Split(expr, "+")
		num1, _ := strconv.Atoi(parts[0])
		num2, _ := strconv.Atoi(parts[1])
		return num1 + num2
	} else {
		log.Fatal("Invalid arithmetic expression")
		return 0
	}
}

func handleConnection(conn net.Conn) {
	defer conn.Close()
	mutex.Lock()
	port := conn.LocalAddr().(*net.TCPAddr).Port
	agentConnected[strconv.Itoa(port)] = "processing" // статус сервера говорящий о процессе вычисления
	mutex.Unlock()
	// Читаем выражение из соединения
	reader := bufio.NewReader(conn)
	expr, _ := reader.ReadString('\n')

	result := evaluateArithmeticExpression(strings.TrimSpace(expr))

	// Отправляем результат обратно оркестратору
	_, err := conn.Write([]byte(strconv.Itoa(result) + "\n"))
	if err != nil {
		log.Fatal(err)
	}
	mutex.Lock()
	port1 := conn.LocalAddr().(*net.TCPAddr).Port
	agentConnected[strconv.Itoa(port1)] = "finisd" // статус сервера говорящий о зевершенни последней операции
	mutex.Unlock()
}

// Функция отправляющая разделенные на части выражения агентам,
// организующая их последовательное выполнение и сожраняющая их
func sendToAgent(expr_map map[int][][]string, ex_to_stat string, rec_id int) {
	exprs := expr_map[rec_id]
	for _, expr2 := range exprs {
		go func(expr2 []string, rec_id int) {
			expr := expr2[0] + expr2[1] + expr2[2]
			n_op := expr2[3]
			if strings.Contains(expr, "op") == true {
				if strings.Contains(expr2[0], "op") == true && strings.Contains(expr2[2], "op") == true {
					p1 := expr2[0]
					p2 := expr2[2]
					need_p1 := ""
					need_p2 := ""
					flag1 := false
					for flag1 != true {
						mutex.Lock()
						for _, q := range db22[rec_id] {
							if q[0] == p1 {
								need_p1 = q[1]
							} else if q[0] == p2 {
								need_p2 = q[1]
							}
						}
						mutex.Unlock()
						if need_p1 != "" && need_p2 != "" {
							expr := need_p1 + expr2[1] + need_p2
							mutex.Lock()
							db, err := sql.Open("sqlite3", "./test.db")
							if err != nil {
								log.Fatal(err)
							}
							defer db.Close()
							data, _, err := ReadAllFromDB(db)
							if err != nil {
								log.Fatal(err)
							}
							// data, _ := ReadFromFile("db.txt")
							agentPort := "8080" // Порт первого агента
							if len(data)%2 == 0 {
								agentPort = "8081" // Порт второго агента
							}
							mutex.Unlock()
							// Соединение с агентом
							conn, err := net.Dial("tcp", "localhost:"+agentPort)
							if err != nil {
								log.Fatal(err)
							}
							defer conn.Close()
							// Отправка выражения агенту
							_, err = conn.Write([]byte(strings.TrimSpace(expr) + "\n"))
							if err != nil {
								log.Println("Error sending expression to agent:", err)
								return
							}
							// Получение результата от агента
							result, err := bufio.NewReader(conn).ReadString('\n')
							if err != nil {
								log.Println("Error reading response from agent:", err)
								return
							}
							result = strings.TrimRight(result, "\n")
							// Сохранение результата в базе данных
							mutex.Lock()
							part := []string{}
							part = append(part, n_op)
							part = append(part, result)
							db22[rec_id] = append(db22[rec_id], part)
							if len(db22[rec_id]) == len_expr[ex_to_stat] {
								db1, err := sql.Open("sqlite3", "./status.db")
								if err != nil {
									log.Fatal(err)
								}
								defer db1.Close()
								// err = UpdateStatusDB(db1, ex_to_stat, "true")
								err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
								// err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
								if err != nil {
									log.Fatal(err)
								}
								// err12 := UpdateStatus("status.txt", ex_to_stat, "true", strconv.Itoa(rec_id))
								// if err12 != nil {
								// 	log.Fatal(err12)
								// }
								db, err := sql.Open("sqlite3", "./test.db")
								if err != nil {
									log.Fatal(err)
								}
								defer db.Close()
								err = WriteToDB(db, ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
								if err != nil {
									log.Fatal(err)
								}
								// err := WriteToFile("db.txt", ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
								// if err != nil {
								// 	log.Fatal(err)
								// }
							}
							mutex.Unlock()
							flag1 = true

						}

					}
				} else if strings.Contains(expr2[0], "op") == true {
					p1 := expr2[0]
					need_p1 := ""
					flag2 := false
					for flag2 != true {
						mutex.Lock()
						for _, q := range db22[rec_id] {
							if q[0] == p1 {
								need_p1 = q[1]
							}
						}
						mutex.Unlock()
						if need_p1 != "" {
							expr := need_p1 + expr2[1] + expr2[2]
							mutex.Lock()
							db, err := sql.Open("sqlite3", "./test.db")
							if err != nil {
								log.Fatal(err)
							}
							defer db.Close()
							data, _, err := ReadAllFromDB(db)
							if err != nil {
								log.Fatal(err)
							}
							// data, _ := ReadFromFile("db.txt")
							agentPort := "8080" // Порт первого агента
							if len(data)%2 == 0 {
								agentPort = "8081" // Порт второго агента
							}
							mutex.Unlock()
							// Соединение с агентом
							conn, err := net.Dial("tcp", "localhost:"+agentPort)
							if err != nil {
								log.Fatal(err)
							}
							defer conn.Close()
							// Отправка выражения агенту
							_, err = conn.Write([]byte(strings.TrimSpace(expr) + "\n"))
							if err != nil {
								log.Println("Error sending expression to agent:", err)
								return
							}
							// Получение результата от агента
							result, err := bufio.NewReader(conn).ReadString('\n')
							if err != nil {
								log.Println("Error reading response from agent:", err)
								return
							}
							result = strings.TrimRight(result, "\n")
							// Сохранение результата в базе данных
							mutex.Lock()
							part := []string{}
							part = append(part, n_op)
							part = append(part, result)
							db22[rec_id] = append(db22[rec_id], part)
							if len(db22[rec_id]) == len_expr[ex_to_stat] {
								db1, err := sql.Open("sqlite3", "./status.db")
								if err != nil {
									log.Fatal(err)
								}
								defer db1.Close()
								// err = UpdateStatusDB(db1, ex_to_stat, "true")
								err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
								// err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
								if err != nil {
									log.Fatal(err)
								}
								// err12 := UpdateStatus("status.txt", ex_to_stat, "true", strconv.Itoa(rec_id))
								// if err12 != nil {
								// 	log.Fatal(err12)
								// }
								db, err := sql.Open("sqlite3", "./test.db")
								if err != nil {
									log.Fatal(err)
								}
								defer db.Close()
								err = WriteToDB(db, ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
								if err != nil {
									log.Fatal(err)
								}
								// err := WriteToFile("db.txt", ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
								// if err != nil {
								// 	log.Fatal(err)
								// }
							}
							mutex.Unlock()
							flag2 = true
						}
					}
				} else if strings.Contains(expr2[2], "op") == true {
					p2 := expr2[2]
					need_p2 := ""
					flag3 := false
					for flag3 != true {
						mutex.Lock()
						for _, q := range db22[rec_id] {
							if q[0] == p2 {
								need_p2 = q[1]
							}
						}
						mutex.Unlock()
						if need_p2 != "" {
							expr := expr2[0] + expr2[1] + need_p2
							mutex.Lock()
							db, err := sql.Open("sqlite3", "./test.db")
							if err != nil {
								log.Fatal(err)
							}
							defer db.Close()
							data, _, err := ReadAllFromDB(db)
							if err != nil {
								log.Fatal(err)
							}
							// data, _ := ReadFromFile("db.txt")
							agentPort := "8080" // Порт первого агента
							if len(data)%2 == 0 {
								agentPort = "8081" // Порт второго агента
							}
							mutex.Unlock()
							// Соединение с агентом
							conn, err := net.Dial("tcp", "localhost:"+agentPort)
							if err != nil {
								log.Fatal(err)
							}
							defer conn.Close()
							// Отправка выражения агенту
							_, err = conn.Write([]byte(strings.TrimSpace(expr) + "\n"))
							if err != nil {
								log.Println("Error sending expression to agent:", err)
								return
							}
							// Получение результата от агента
							result, err := bufio.NewReader(conn).ReadString('\n')
							if err != nil {
								log.Println("Error reading response from agent:", err)
								return
							}
							result = strings.TrimRight(result, "\n")
							// Сохранение результата в базе данных
							mutex.Lock()
							part := []string{}
							part = append(part, n_op)
							part = append(part, result)
							db22[rec_id] = append(db22[rec_id], part)
							if len(db22[rec_id]) == len_expr[ex_to_stat] {
								db1, err := sql.Open("sqlite3", "./status.db")
								if err != nil {
									log.Fatal(err)
								}
								defer db1.Close()
								// err = UpdateStatusDB(db1, ex_to_stat, "true")
								err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
								// err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
								if err != nil {
									log.Fatal(err)
								}
								// err12 := UpdateStatus("status.txt", ex_to_stat, "true", strconv.Itoa(rec_id))
								// if err12 != nil {
								// 	log.Fatal(err12)
								// }
								db, err := sql.Open("sqlite3", "./test.db")
								if err != nil {
									log.Fatal(err)
								}
								defer db.Close()
								err = WriteToDB(db, ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
								if err != nil {
									log.Fatal(err)
								}
								// err := WriteToFile("db.txt", ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
								// if err != nil {
								// 	log.Fatal(err)
								// }
							}
							mutex.Unlock()
							flag3 = true
						}
					}
				}
			} else {
				// Определение порта агента для обработки выражения
				mutex.Lock()
				db, err := sql.Open("sqlite3", "./test.db")
				if err != nil {
					log.Fatal(err)
				}
				defer db.Close()
				data, _, err := ReadAllFromDB(db)
				if err != nil {
					log.Fatal(err)
				}
				// data, _ := ReadFromFile("db.txt")
				agentPort := "8080" // Порт первого агента
				if len(data)%2 == 0 {
					agentPort = "8081" // Порт второго агента
				}
				mutex.Unlock()
				// Соединение с агентом
				conn, err := net.Dial("tcp", "localhost:"+agentPort)
				if err != nil {
					log.Fatal(err)
				}
				defer conn.Close()

				// Отправка выражения агенту
				_, err = conn.Write([]byte(strings.TrimSpace(expr) + "\n"))
				if err != nil {
					log.Println("Error sending expression to agent:", err)
					return
				}

				// Получение результата от агента
				result, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					log.Println("Error reading response from agent:", err)
					return
				}
				result = strings.TrimRight(result, "\n")
				// Сохранение результата в базе данных

				mutex.Lock()
				part := []string{}
				part = append(part, n_op)
				part = append(part, result)
				db22[rec_id] = append(db22[rec_id], part)
				if len(db22[rec_id]) == len_expr[ex_to_stat] {
					db1, err := sql.Open("sqlite3", "./status.db")
					if err != nil {
						log.Fatal(err)
					}
					defer db1.Close()
					// err = UpdateStatusDB(db1, ex_to_stat, "true")
					err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
					// err = UpdateStatusDB(db1, ex_to_stat, "true", strconv.Itoa(rec_id))
					if err != nil {
						log.Fatal(err)
					}
					// err12 := UpdateStatus("status.txt", ex_to_stat, "true", strconv.Itoa(rec_id))
					// if err12 != nil {
					// 	log.Fatal(err12)
					// }
					db, err := sql.Open("sqlite3", "./test.db")
					if err != nil {
						log.Fatal(err)
					}
					defer db.Close()
					err = WriteToDB(db, ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
					if err != nil {
						log.Fatal(err)
					}
					// err := WriteToFile("db.txt", ex_to_stat, db22[rec_id][len(db22[rec_id])-1][1])
					// if err != nil {
					// 	log.Fatal(err)
					// }
				}
				mutex.Unlock()
			}
		}(expr2, rec_id)
	}
}

func maxOperand(slice []string) (operand string) {
	var maxStr string
	var maxNum int

	for _, str := range slice {
		match := regexp.MustCompile(`op(\d+)`).FindStringSubmatch(str)
		if len(match) > 1 {
			num, _ := strconv.Atoi(match[1])
			if num > maxNum {
				maxNum = num
				maxStr = str
			}
		}
	}
	return maxStr
}

func sliseContains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}

func splitExpression(expr string) []string {
	re := regexp.MustCompile(`(\d+|\+|\-|\*|\/)`)
	matches := re.FindAllString(expr, -1)
	return matches
}

// проверка выражения на корректность
func checkArithmeticExpression(s string) bool {
	allowedChars := "0123456789+-*/"
	numStarted := false
	for i, char := range s {
		if !strings.ContainsRune(allowedChars, char) {
			return false
		}
		if char >= '0' && char <= '9' {
			if !numStarted {
				numStarted = true
			}
		} else {
			if numStarted && (char != '+' && char != '-' && char != '*' && char != '/') {
				return false
			}
			if i > 0 && s[i-1] != ' ' && s[i-1] != '0' && s[i-1] != '1' && s[i-1] != '2' && s[i-1] != '3' && s[i-1] != '4' && s[i-1] != '5' && s[i-1] != '6' && s[i-1] != '7' && s[i-1] != '8' && s[i-1] != '9' {
				return false
			}
			numStarted = false
		}
	}
	return true
}

// разбивка полученного выражения на части, которые будут отсылаться агентам
func parseExpr(expr string, ri int) (map_expr map[int][][]string, err string) {
	operation_list := make(map[int][][]string, 0)
	expr2 := splitExpression(expr)
	midl_sl := [][]string{}
	if len(expr2) == 3 {
		sr := []string{}
		sr = append(sr, expr2[0])
		sr = append(sr, expr2[1])
		sr = append(sr, expr2[2])
		sr = append(sr, "op"+strconv.Itoa(1))
		midl_sl = append(midl_sl, sr)
	} else {
		k := 1
		used_index := []string{}
		index := []int{}
		for i, n := range expr2 {
			if n == "*" || n == "/" {
				if sliseContains(index, i-1) == false && sliseContains(index, i) == false && sliseContains(index, i+1) == false {
					sr := []string{}
					sr = append(sr, expr2[i-1])
					sr = append(sr, expr2[i])
					sr = append(sr, expr2[i+1])
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				} else if sliseContains(index, i-1) == true && sliseContains(index, i) == false && sliseContains(index, i+1) == false {
					sr := []string{}
					fp := ""
					fp_slise := []string{}
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i-1) == used_index[j] {
							fp = used_index[j+1]
							fp_slise = append(fp_slise, fp)
						}
					}
					fp = maxOperand(fp_slise)

					sr = append(sr, fp)
					sr = append(sr, expr2[i])
					sr = append(sr, expr2[i+1])

					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				} else if sliseContains(index, i-1) == false && sliseContains(index, i) == false && sliseContains(index, i+1) == true {
					sr := []string{}
					fp := ""
					fp_slise := []string{}
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i+1) == used_index[j] {
							fp = used_index[j+1]
							fp_slise = append(fp_slise, fp)
						}
					}
					fp = maxOperand(fp_slise)

					sr = append(sr, expr2[i-1])
					sr = append(sr, expr2[i])
					sr = append(sr, fp)
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				} else if sliseContains(index, i-1) == true && sliseContains(index, i) == false && sliseContains(index, i+1) == true {
					sr := []string{}
					fp := ""
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i-1) == used_index[j] {
							fp = used_index[j+1]
							break
						}
					}
					fp1 := ""
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i+1) == used_index[j] {
							fp1 = used_index[j+1]
							break
						}
					}

					sr = append(sr, fp)
					sr = append(sr, expr2[i])
					sr = append(sr, fp1)
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				}

			}
		}
		for i, n := range expr2 {
			if n == "+" || n == "-" {
				if sliseContains(index, i-1) == false && sliseContains(index, i) == false && sliseContains(index, i+1) == false {
					sr := []string{}
					sr = append(sr, expr2[i-1])
					sr = append(sr, expr2[i])
					sr = append(sr, expr2[i+1])
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)
					midl_sl = append(midl_sl, sr)
					k += 1
				} else if sliseContains(index, i-1) == true && sliseContains(index, i) == false && sliseContains(index, i+1) == false {
					sr := []string{}
					fp := ""
					fp_slise := []string{}
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i-1) == used_index[j] {
							fp = used_index[j+1]
							fp_slise = append(fp_slise, fp)
						}
					}
					if len(fp_slise) > 1 {
						fp = maxOperand(fp_slise)
					} else {
						fp = maxOperand(fp_slise)
						for _, g := range midl_sl {
							if g[0] == fp || g[2] == fp {
								fp = g[3]
							}
						}
					}

					sr = append(sr, fp)
					sr = append(sr, expr2[i])
					sr = append(sr, expr2[i+1])
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				} else if sliseContains(index, i-1) == false && sliseContains(index, i) == false && sliseContains(index, i+1) == true {
					sr := []string{}
					fp := ""
					fp_slise := []string{}
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i+1) == used_index[j] {
							fp = used_index[j+1]
							fp_slise = append(fp_slise, fp)
						}
					}
					if len(fp_slise) > 1 {
						fp = maxOperand(fp_slise)
					} else {
						fp = maxOperand(fp_slise)
						for _, g := range midl_sl {
							if g[0] == fp || g[2] == fp {
								fp = g[3]
							}
						}
					}

					sr = append(sr, expr2[i-1])
					sr = append(sr, expr2[i])
					sr = append(sr, fp)
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				} else if sliseContains(index, i-1) == true && sliseContains(index, i) == false && sliseContains(index, i+1) == true {
					sr := []string{}
					fp := ""
					fp_slise := []string{}
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i-1) == used_index[j] {
							fp = used_index[j+1]
							fp_slise = append(fp_slise, fp)
						}
					}
					if len(fp_slise) > 1 {
						fp = maxOperand(fp_slise)
					} else {
						fp = maxOperand(fp_slise)
						for _, g := range midl_sl {
							if g[0] == fp || g[2] == fp {
								fp = g[3]
							}
						}
					}

					fp1 := ""
					fp_slise1 := []string{}
					for j := 0; j < len(used_index); j += 2 {
						if strconv.Itoa(i+1) == used_index[j] {
							fp1 = used_index[j+1]
							fp_slise1 = append(fp_slise1, fp1)
						}
					}
					if len(fp_slise1) > 1 {
						fp1 = maxOperand(fp_slise1)
					} else {
						fp1 = maxOperand(fp_slise1)
						for _, g := range midl_sl {
							if g[0] == fp1 || g[2] == fp1 {
								fp1 = g[3]
							}
						}
					}
					sr = append(sr, fp)
					sr = append(sr, expr2[i])
					sr = append(sr, fp1)
					used_index = append(used_index, strconv.Itoa(i-1), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i), "op"+strconv.Itoa(k))
					used_index = append(used_index, strconv.Itoa(i+1), "op"+strconv.Itoa(k))
					sr = append(sr, "op"+strconv.Itoa(k))

					index = append(index, i-1)
					index = append(index, i)
					index = append(index, i+1)

					midl_sl = append(midl_sl, sr)
					k += 1
				}
			}
		}
	}
	operation_list[ri] = midl_sl
	return operation_list, "200. Выражение успешно принято, распаршено и принято к обработке"
}

func UpdateStatusDB(db *sql.DB, key, value, id string) error {
	// Обновление значения
	value1 := value + " " + id
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM status WHERE key=?)", key).Scan(&exists)
	if err != nil {
		return err
	}
	// Если ключ существует, обновляем значение
	if exists {
		_, err = db.Exec("UPDATE status SET value=? WHERE key=?", value1, key)
	} else {
		// Иначе, вставляем новую пару ключ-значение
		_, err = db.Exec("INSERT INTO status(key, value) VALUES(?, ?)", key, value1)
	}
	return err
}

func GetAllStatusDB(db *sql.DB) (map[string]string, error) {
	rows, err := db.Query("SELECT key, value FROM status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	data := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, err
		}
		data[key] = value
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return data, nil
}

func GetStatus(filename string) (map[string]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	data := make(map[string]string)

	for scanner.Scan() {
		line := scanner.Text()
		if idx := strings.Index(line, "="); idx > 0 {
			key := line[:idx]
			value := line[idx+1:]
			data[key] = value
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return data, nil
}

func AddIdToDB(db *sql.DB, key, id string) error {
	// Проверяем, существует ли ключ в базе данных
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM kv WHERE key=?)", key).Scan(&exists)
	if err != nil {
		return err
	}
	old_id, _ := ReadFromDB(db, key)
	ids := strings.Split(old_id, ";")
	ids = append(ids, id)
	new_id := strings.Join(ids, ";")
	// Если ключ существует, обновляем значение
	if exists {
		_, err = db.Exec("UPDATE kv SET id=? WHERE key=?", new_id, key)
	} else {
		// Иначе, вставляем новую пару ключ-значение
		_, err = db.Exec("INSERT INTO kv(key, id) VALUES(?, ?)", key, new_id)
	}

	return err
}

func WriteNewToDB(db *sql.DB, key, value, id string) error {
	// Проверяем, существует ли ключ в базе данных
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM kv WHERE key=?)", key).Scan(&exists)
	if err != nil {
		return err
	}

	// Если ключ существует, обновляем значение
	if exists {
		_, err = db.Exec("UPDATE kv SET value=?, id=? WHERE key=?", value, key, id)
	} else {
		// Иначе, вставляем новую пару ключ-значение
		_, err = db.Exec("INSERT INTO kv(key, value, id) VALUES(?, ?, ?)", key, value, id)
	}

	return err
}

func WriteToDB(db *sql.DB, key, value string) error {
	// Проверяем, существует ли ключ в базе данных
	var exists bool
	err := db.QueryRow("SELECT EXISTS(SELECT 1 FROM kv WHERE key=?)", key).Scan(&exists)
	if err != nil {
		return err
	}

	// Если ключ существует, обновляем значение
	if exists {
		_, err = db.Exec("UPDATE kv SET value=? WHERE key=?", value, key)
	} else {
		// Иначе, вставляем новую пару ключ-значение
		_, err = db.Exec("INSERT INTO kv(key, value) VALUES(?, ?)", key, value)
	}

	return err
}

func ReadFromDB(db *sql.DB, key string) (string, error) {
	var id string
	err := db.QueryRow("SELECT id FROM kv WHERE key=?", key).Scan(&id)
	if err != nil {
		if err == sql.ErrNoRows {
			// Ключ не найден, возвращаем ошибку
			return "", fmt.Errorf("key not found: %s", key)
		}
		return "", err
	}
	return id, nil
}

func ReadAllFromDB(db *sql.DB) (map[string]string, []string, error) {
	rows1, err1 := db.Query("SELECT id FROM kv")
	if err1 != nil {
		return nil, nil, err1
	}
	defer rows1.Close()
	data1 := []string{}
	for rows1.Next() {
		var id string
		if err := rows1.Scan(&id); err != nil {
			return nil, nil, err
		}
		data1 = append(data1, id)
	}
	rows, err := db.Query("SELECT key, value FROM kv")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()

	data := make(map[string]string)
	for rows.Next() {
		var key, value string
		if err := rows.Scan(&key, &value); err != nil {
			return nil, nil, err
		}
		data[key] = value
	}

	if err := rows.Err(); err != nil {
		return nil, nil, err
	}

	return data, data1, nil
}

func ReadAllFromDB1(db *sql.DB) (map[string]map[string]string, error) {
	// Запрос для получения всех id
	rows1, err1 := db.Query("SELECT id FROM kv")
	if err1 != nil {
		return nil, err1
	}
	defer rows1.Close()

	// Создаем внешнюю карту для хранения данных
	data := make(map[string]map[string]string)

	// Запрос для получения всех пар ключ-значение
	rows, err := db.Query("SELECT id, key, value FROM kv")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var id, key, value string
		if err := rows.Scan(&id, &key, &value); err != nil {
			return nil, err
		}

		// Проверяем, существует ли уже внешний ключ в карте
		if _, exists := data[id]; !exists {
			// Если нет, создаем внутреннюю карту для этого id
			data[id] = make(map[string]string)
		}

		// Добавляем ключ и значение во внутреннюю карту
		data[id][key] = value
	}

	if err := rows.Err(); err != nil {
		return nil, err
	}

	return data, nil
}

func CreateNewRecord(db *sql.DB) error {
	_, err := db.Exec("INSERT INTO ink DEFAULT VALUES")
	return err
}

func GetLastInsertID(db *sql.DB) (int64, error) {
	var lastID int64
	err := db.QueryRow("SELECT last_insert_rowid()").Scan(&lastID)
	return lastID, err
}

// основная функция работающая с выражением
func Orchestrat(w http.ResponseWriter, r *http.Request) {
	expr := r.URL.Query().Get("expr")
	var message string
	message = "400. Выражение невалидно"
	// проверка выражения
	if checkArithmeticExpression(expr) == true && strings.Contains(expr, " ") == false && expr != "" {
		db, err := sql.Open("sqlite3", "./test.db")
		if err != nil {
			log.Fatal(err)
		}
		defer db.Close()

		data1, err := ReadAllFromDB1(db)
		if err != nil {
			log.Fatal(err)
		}
		repiated_expr := false

		for id, innerMap := range data1 {
			expr_id := []string{}
			if strings.Contains(id, ";") {
				expr_id = strings.Split(id, ";")
			} else {
				expr_id = append(expr_id, id)
			}
			for k, _ := range innerMap {
				if k == expr {
					if slices.Contains(expr_id, strconv.Itoa(sesesion_id)) {
						repiated_expr = true
					} else {
						db, err := sql.Open("sqlite3", "./test.db")
						if err != nil {
							log.Fatal(err)
						}
						defer db.Close()
						err = AddIdToDB(db, expr, strconv.Itoa(sesesion_id))
						repiated_expr = true
					}
				}
			}
		}
		if repiated_expr == false {
			db4, err := sql.Open("sqlite3", "./ink.db")
			if err != nil {
				log.Fatal(err)
			}
			defer db4.Close()

			err = CreateNewRecord(db4)
			if err != nil {
				log.Fatal(err)
			}

			lastID, err := GetLastInsertID(db4)
			if err != nil {
				log.Fatal(err)
			}
			ri := int(lastID)
			db1, err := sql.Open("sqlite3", "./status.db")
			if err != nil {
				log.Fatal(err)
			}
			defer db1.Close()
			err = UpdateStatusDB(db1, expr, "false", strconv.Itoa(ri))
			if err != nil {
				log.Fatal(err)
			}

			pars, _ := parseExpr(expr, ri)

			db, err := sql.Open("sqlite3", "./test.db")
			if err != nil {
				log.Fatal(err)
			}
			defer db.Close()
			err = WriteNewToDB(db, expr, "?", strconv.Itoa(sesesion_id))
			if err != nil {
				log.Fatal(err)
			}
			recvest_id[expr] = ri
			len_expr[expr] = len(pars[ri])
			sendToAgent(pars, expr, ri)
			message = "200. Выражение успешно принято, распаршено и принято к обработке"
		} else {
			message = "200. Выражение успешно принято, распаршено и принято к обработке"
		}
	}
	tmpl, err := template.ParseFiles("html/orchestrat.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// вывод сообщения
	data := map[string]string{
		"Message": message,
	}
	err = tmpl.Execute(w, data)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Страница с выражениями
func Storage(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("html/storage.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	data1, err := ReadAllFromDB1(db)
	if err != nil {
		log.Fatal(err)
	}

	personal_data := make(map[string]string)

	for id, innerMap := range data1 {
		expr_id_st := []string{}
		if strings.Contains(id, ";") {
			expr_id_st = strings.Split(id, ";")
		} else {
			expr_id_st = append(expr_id_st, id)
		}
		if slices.Contains(expr_id_st, strconv.Itoa(sesesion_id)) {
			for k, v := range innerMap {
				personal_data[k] = v
			}
		}
	}
	tmpl.Execute(w, personal_data)
}

func Agents(w http.ResponseWriter, r *http.Request) {
	tmpl, err := template.ParseFiles("html/agents.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	agentStatus := make(map[string]string)
	for port, connected := range agentConnected {
		agentStatus[port] = connected
	}
	tmpl.Execute(w, agentStatus)
}

// Определение структуры для передачи данных в шаблон HTML
type OperationForm struct {
	AdditionSeconds       int
	SubtractionSeconds    int
	MultiplicationSeconds int
	DivisionSeconds       int
}

func OperationTime(w http.ResponseWriter, r *http.Request) {
	// Проверка метода запроса
	if r.Method == "POST" {
		// Обновление глобальных переменных из POST-запроса
		additionSeconds = getFormValue(r, "addition")
		subtractionSeconds = getFormValue(r, "subtraction")
		multiplicationSeconds = getFormValue(r, "multiplication")
		divisionSeconds = getFormValue(r, "division")
	}

	// Создание структуры с текущими значениями
	form := OperationForm{
		AdditionSeconds:       additionSeconds,
		SubtractionSeconds:    subtractionSeconds,
		MultiplicationSeconds: multiplicationSeconds,
		DivisionSeconds:       divisionSeconds,
	}

	// Шаблон HTML для формы
	tmpl, err := template.ParseFiles("html/operations.tmpl")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Обработка ошибок при рендеринге шаблона
	if err := tmpl.Execute(w, form); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// Функция для обновление глобальных переменных из POST-запроса
func getFormValue(r *http.Request, key string) int {
	value := r.FormValue(key)
	intValue, err := strconv.Atoi(value)
	if err != nil {
		fmt.Println("Error parsing form value:", err)
		return 0
	}
	return intValue
}

// главная страница
func serveStaticFile(filename string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		http.ServeFile(w, r, filename)
	}
}

func main() {
	db, err := sql.Open("sqlite3", "./test.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec("CREATE TABLE IF NOT EXISTS kv (key TEXT PRIMARY KEY, value TEXT, id TEXT)")
	if err != nil {
		log.Fatal(err)
	}

	db1, err := sql.Open("sqlite3", "./status.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db1.Close()

	_, err = db1.Exec("CREATE TABLE IF NOT EXISTS status (key TEXT PRIMARY KEY, value TEXT)")
	if err != nil {
		log.Fatal(err)
	}

	db2, err := sql.Open("sqlite3", "./users.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db2.Close()

	_, err = db2.Exec("CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, Login TEXT NOT NULL UNIQUE, Password TEXT NOT NULL)")
	if err != nil {
		log.Fatal(err)
	}

	db3, err := sql.Open("sqlite3", "./ink.db")
	if err != nil {
		log.Fatal(err)
	}
	defer db3.Close()
	_, err = db3.Exec("CREATE TABLE IF NOT EXISTS ink (id INTEGER PRIMARY KEY AUTOINCREMENT)")
	if err != nil {
		log.Fatal(err)
	}

	// установка значений по умолчанию
	additionSeconds = 5
	subtractionSeconds = 5
	multiplicationSeconds = 5
	divisionSeconds = 5
	agentConnected["8080"] = "waiting"
	agentConnected["8081"] = "waiting"

	// Запуск первого агента
	listener1, err := net.Listen("tcp", ":8080")
	if err != nil {
		log.Fatal(err)
	}
	defer listener1.Close()

	go func() {
		for {
			conn, err := listener1.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go handleConnection(conn)
		}
	}()

	// Запуск второго агента
	listener2, err := net.Listen("tcp", ":8081")
	if err != nil {
		log.Fatal(err)
	}
	defer listener2.Close()

	go func() {
		for {
			conn, err := listener2.Accept()
			if err != nil {
				log.Fatal(err)
			}
			go handleConnection(conn)
		}
	}()

	// Получаем все значения из базы данных
	status_data, err := GetAllStatusDB(db1)
	if err != nil {
		log.Fatal(err)
	}
	// status_data, err := GetStatus("status.txt")
	if err != nil {
		log.Fatal(err)
	}
	for key, status := range status_data {
		status_id := strings.Split(status, " ")
		status1 := status_id[0]
		id, _ := strconv.Atoi(status_id[1])
		if status1 == "false" {
			pars, _ := parseExpr(key, id)
			recvest_id[key] = id
			len_expr[key] = len(pars[id])
			sendToAgent(pars, key, id)
		}
	}

	http.Handle("/api/v1/register", http.HandlerFunc(RegisterHandler))
	http.Handle("/api/v1/login", http.HandlerFunc(LoginHandler))
	http.Handle("/operations", Middleware(http.HandlerFunc(OperationTime)))
	http.Handle("/calculate", Middleware(http.HandlerFunc(Orchestrat)))
	http.Handle("/storage", Middleware(http.HandlerFunc(Storage)))
	http.Handle("/agents", Middleware(http.HandlerFunc(Agents)))
	http.Handle("/", Middleware(http.HandlerFunc(serveStaticFile("html/index.html"))))
	log.Println("Starting HTTP server on localhost:8082")
	go log.Fatal(http.ListenAndServe(":8082", nil))
	select {}
}
