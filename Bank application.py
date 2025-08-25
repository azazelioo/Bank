from tkinter import *
from tkinter import messagebox
import sqlite3
import random
import bcrypt
import os  


script_dir = os.path.dirname(os.path.abspath(__file__))

db_path = os.path.join(script_dir, "Bank.db")

Alf = "ёйцукенгшщзхъфывапролджэячсмитьбю"
Alf += Alf.upper()

def check_enter_symbols(s):
    for i in s:
        if (i in Alf) == False:
            return False
    return True


conn = sqlite3.connect(db_path)
cursor = conn.cursor()


cursor.execute('''CREATE TABLE IF NOT EXISTS Users 
                 (id INTEGER PRIMARY KEY,
                 Login TEXT NOT NULL UNIQUE,
                 Password BLOB NOT NULL)''')

cursor.execute('''CREATE TABLE IF NOT EXISTS Accounts 
                (id INTEGER PRIMARY KEY,
                user_id INTEGER NOT NULL,
                First_name TEXT,
                Last_name TEXT,
                bank_account TEXT,
                balance REAL DEFAULT 1000.0,
                FOREIGN KEY (user_id) REFERENCES Users(id))''')
conn.commit()

class AuthApp:
    def __init__(self):
        self.root = Tk()
        self.root.title("Банковская система - Авторизация")
        self.root.geometry("500x400")
        self.root.resizable(False, False)
        self.center_window(self.root, 500, 400)
        self.create_auth_widgets()
    
    def center_window(self, window, width, height):
        window.update_idletasks()
        position_right = int(window.winfo_screenwidth()/2 - width/2)
        position_down = int(window.winfo_screenheight()/2 - height/2)
        window.geometry(f"{width}x{height}+{position_right}+{position_down}")
    
    def create_auth_widgets(self):
        main_frame = Frame(self.root)
        main_frame.pack(expand=True, fill=BOTH, padx=20, pady=20)
        
        Label(main_frame, text="Авторизация", 
              font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        input_frame = Frame(main_frame)
        input_frame.pack(fill=X, pady=10) 
        
        Label(input_frame, text="Логин:", font=("Arial", 12)).grid(row=0, column=0, sticky=W, pady=5)
        self.login_entry = Entry(input_frame, font=("Arial", 12))
        self.login_entry.grid(row=0, column=1, sticky=EW, pady=5, padx=5)
        
        Label(input_frame, text="Пароль:", font=("Arial", 12)).grid(row=1, column=0, sticky=W, pady=5)
        self.password_entry = Entry(input_frame, show="*", font=("Arial", 12))
        self.password_entry.grid(row=1, column=1, sticky=EW, pady=5, padx=5)
        
        self.show_pass = BooleanVar()
        Checkbutton(input_frame, text="Показать пароль", font=("Arial", 10),
                   variable=self.show_pass, command=self.toggle_password).grid(row=2, column=1, sticky=W, padx=5)
        
        self.login_btn = Button(main_frame, text="Войти", 
                              font=("Arial", 12, "bold"), bg="#2196F3", fg="white",
                              command=self.check_data)
        self.login_btn.pack(pady=20, ipadx=10, ipady=5)
        
        reg_frame = Frame(main_frame)
        reg_frame.pack(fill=X)
        
        Label(reg_frame, text="Нет аккаунта?", font=("Arial", 10)).pack(side=LEFT, padx=5)
        self.reg_link = Label(reg_frame, text="Зарегистрироваться", 
                            font=("Arial", 10, "underline"), fg="blue", cursor="hand2")
        self.reg_link.pack(side=LEFT)
        self.reg_link.bind("<Button-1>", lambda e: self.open_registration())
        
        input_frame.grid_columnconfigure(1, weight=1)
        
        self.login_btn.bind("<Enter>", lambda e: self.login_btn.config(bg="#0b7dda"))
        self.login_btn.bind("<Leave>", lambda e: self.login_btn.config(bg="#2196F3"))
        
        self.login_entry.bind("<Return>", lambda e: self.password_entry.focus())
        self.password_entry.bind("<Return>", lambda e: self.check_data())
        
        self.login_entry.focus_set()
    
    def open_registration(self):
        registration_window = Registor(self.root)
        self.root.wait_window(registration_window.window)
    
    def toggle_password(self):
        if self.show_pass.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")
    
    def check_data(self, event=None):
        login = self.login_entry.get()
        password = self.password_entry.get()
        
        if not login or not password:
            messagebox.showerror("Ошибка", "Все поля должны быть заполнены!")
            return
            
        try:
            cursor.execute('''SELECT id, Password FROM Users WHERE Login = ?''', (login,))
            result = cursor.fetchone()
            
            if result:
                user_id, stored_hash = result
                if bcrypt.checkpw(password.encode('utf-8'), stored_hash):
                    self.open_mainapp(user_id)
                else:
                    messagebox.showerror("Ошибка", "Неверный пароль")
            else:
                messagebox.showerror("Ошибка", "Пользователь не найден")
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")
    
    def open_mainapp(self, user_id):
        self.root.withdraw()
        MainApp(self.root, user_id)
    
    def run(self):
        self.root.mainloop()

class Registor:
    def __init__(self, master):
        self.master = master
        self.window = Toplevel(master)
        self.window.title("Регистрация")
        self.window.geometry("500x500")
        self.window.resizable(False, False)
        self.center_window(self.window, 500, 500)
        
        self.window.after(100, self.set_grab)
        self.create_widgets()
    
    def set_grab(self):
        self.window.grab_set()
    
    def center_window(self, window, width, height):
        window.update_idletasks()
        position_right = int(window.winfo_screenwidth()/2 - width/2)
        position_down = int(window.winfo_screenheight()/2 - height/2)
        window.geometry(f"{width}x{height}+{position_right}+{position_down}")
    
    def create_widgets(self):
        main_frame = Frame(self.window)
        main_frame.pack(expand=True, fill=BOTH, padx=20, pady=20)
        
        Label(main_frame, text="Регистрация нового аккаунта", 
              font=("Arial", 16, "bold")).pack(pady=(0, 20))
        
        input_frame = Frame(main_frame)
        input_frame.pack(fill=X)
        
        Label(input_frame, text="Логин*:", font=("Arial", 12)).grid(row=0, column=0, sticky=W, pady=5)
        self.login_entry = Entry(input_frame, font=("Arial", 12))
        self.login_entry.grid(row=0, column=1, sticky=EW, pady=5, padx=5)
        
        Label(input_frame, text="Пароль*:", font=("Arial", 12)).grid(row=1, column=0, sticky=W, pady=5)
        self.password_entry1 = Entry(input_frame, show="•", font=("Arial", 12))
        self.password_entry1.grid(row=1, column=1, sticky=EW, pady=5, padx=5)

        Label(input_frame, text="Повторите пароль*:", font=("Arial", 12)).grid(row=2, column=0, sticky=W, pady=5)
        self.password_entry2 = Entry(input_frame, show="•", font=("Arial", 12))
        self.password_entry2.grid(row=2, column=1, sticky=EW, pady=5, padx=5)
        
        self.show_pass = BooleanVar()
        Checkbutton(input_frame, text="Показать пароль", font=("Arial", 10),
                   variable=self.show_pass, command=self.toggle_password).grid(row=3, column=1, sticky=W, padx=5)
        
        self.pass_strength = Label(input_frame, text="", font=("Arial", 9))
        self.pass_strength.grid(row=4, column=1, sticky=W, padx=5)
        self.password_entry2.bind("<KeyRelease>", self.check_password_strength)
        self.password_entry1.bind("<KeyRelease>", self.check_password_strength)
        
        Label(input_frame, text="Фамилия*:", font=("Arial", 12)).grid(row=5, column=0, sticky=W, pady=5)
        self.last_name_entry = Entry(input_frame, font=("Arial", 12))
        self.last_name_entry.grid(row=5, column=1, sticky=EW, pady=5, padx=5)
        
        Label(input_frame, text="Имя*:", font=("Arial", 12)).grid(row=6, column=0, sticky=W, pady=5)
        self.first_name_entry = Entry(input_frame, font=("Arial", 12))
        self.first_name_entry.grid(row=6, column=1, sticky=EW, pady=5, padx=5)
        
        self.reg_btn = Button(main_frame, text="Зарегистрироваться", 
                            font=("Arial", 12, "bold"), bg="#4CAF50", fg="white",
                            command=self.register)
        self.reg_btn.pack(pady=20, ipadx=10, ipady=5)
        
        self.reg_btn.bind("<Enter>", lambda e: self.reg_btn.config(bg="#45a049"))
        self.reg_btn.bind("<Leave>", lambda e: self.reg_btn.config(bg="#4CAF50"))
        
        self.login_entry.bind("<Return>", lambda e: self.password_entry1.focus())
        self.password_entry1.bind("<Return>", lambda e: self.password_entry2.focus())
        self.password_entry2.bind("<Return>", lambda e: self.last_name_entry.focus())
        self.last_name_entry.bind("<Return>", lambda e: self.first_name_entry.focus())
        self.first_name_entry.bind("<Return>", lambda e: self.register())
        
        input_frame.grid_columnconfigure(1, weight=1)
        self.login_entry.focus_set()
    
    def toggle_password(self):
        if self.show_pass.get():
            self.password_entry1.config(show="")
            self.password_entry2.config(show="")
        else:
            self.password_entry1.config(show="*")
            self.password_entry2.config(show="*")
    
    def check_password_strength(self, event):
        password = self.password_entry2.get()
        if not password:
            self.pass_strength.config(text="", fg="gray")
            return
        
        strength = sum([
            len(password) >= 8,
            any(c.isupper() for c in password),
            any(c.islower() for c in password),
            any(c.isdigit() for c in password)
        ])
        
        if strength == 0:
            text, color = "Очень слабый", "red"
        elif strength <= 2:
            text, color = "Слабый", "orange"
        elif strength == 3:
            text, color = "Средний", "blue"
        else:
            text, color = "Сильный", "green"
        
        self.pass_strength.config(text=f"Уровень сложности: {text}", fg=color)
    
    def is_password_strong(self, password):
        return (len(password) >= 8 and
                any(c.isupper() for c in password) and
                any(c.islower() for c in password) and
                any(c.isdigit() for c in password))
    
    def register(self):
        login = self.login_entry.get()
        password1 = self.password_entry1.get()
        password2 = self.password_entry2.get()
        last_name = self.last_name_entry.get()
        first_name = self.first_name_entry.get()

        cursor.execute('''SELECT 1 FROM Users WHERE Login = ?''', (login,))
        
        if not all([login, password1, password2, last_name, first_name]):
            messagebox.showerror("Ошибка", "Все поля обязательны для заполнения!")
            return
            
        if not self.is_password_strong(password1):
            messagebox.showerror("Ошибка", 
                "Пароль должен содержать:\n- Минимум 8 символов\n- Буквы в верхнем и нижнем регистре\n- Хотя бы одну цифру")
            return
            
        if password1 != password2:
            messagebox.showerror("Ошибка", "Пароли не совпадают")
            return 
            
        if check_enter_symbols(last_name) == False or check_enter_symbols(first_name) == False:
            messagebox.showerror("Ошибка", "Фамилия или имя содержат недопустимые символы")
            return
            
        if cursor.fetchone():
            messagebox.showerror("Ошибка", "Такой логин уже существует!")
            return    
            
        try:
            hashed_password = bcrypt.hashpw(password1.encode('utf-8'), bcrypt.gensalt())
            
            cursor.execute('INSERT INTO Users (Login, Password) VALUES (?,?)', 
                         (login, hashed_password))
            user_id = cursor.lastrowid
            
            cursor.execute('''INSERT INTO Accounts 
                           (user_id, First_name, Last_name, bank_account, balance) 
                           VALUES (?,?,?,?,?)''', 
                           (user_id, first_name, last_name, 
                           f"ACC{random.randint(10_000_000, 99_999_999)}", 
                           1000.0))
            
            conn.commit()
            messagebox.showinfo("Успех", "Регистрация завершена успешно!")
            self.window.destroy()
            
        except sqlite3.IntegrityError:
            conn.rollback()
            messagebox.showerror("Ошибка", "Такой логин уже существует!")
        except Exception as e:
            conn.rollback()
            messagebox.showerror("Ошибка", f"Произошла ошибка: {str(e)}")

class MainApp:
    def __init__(self, master, id):
        self.master = master
        self.id = id

        script_dir = os.path.dirname(os.path.abspath(__file__))
        db_path = os.path.join(script_dir, "Bank.db")
        self.conn = sqlite3.connect(db_path)
        self.cursor = self.conn.cursor()
        
        self.window = Toplevel(master)
        self.window.title("Главное приложение")
        self.window.geometry("800x600")
        self.window.protocol("WM_DELETE_WINDOW", self.on_close)
        
        try:
            self.cursor.execute('SELECT * FROM Accounts WHERE user_id = ?', (self.id,))
            self.account_data = self.cursor.fetchone()
            
            if self.account_data:
                self.create_widgets()
            else:
                messagebox.showerror("Ошибка", "Данные аккаунта не найдены")
                self.window.destroy()
                
        except Exception as e:
            messagebox.showerror("Ошибка", f"Ошибка: {str(e)}")
            self.window.destroy()

    def create_widgets(self):
        Label(self.window, text=f"Добро пожаловать, {self.account_data[2]} {self.account_data[3]}!", 
              font=("Arial", 14)).pack(pady=20)
        
        Label(self.window, text=f"Ваш счет: {self.account_data[4]}", 
              font=("Arial", 12)).pack(pady=10)
        
        Label(self.window, text=f"Баланс: {self.account_data[5]:.2f} руб.", 
              font=("Arial", 12)).pack(pady=10)
        
    def on_close(self):
        self.cursor.close()
        self.conn.close()
        self.window.destroy()
        self.master.deiconify()

if __name__ == "__main__":
    app = AuthApp()
    app.run()

    conn.close()
