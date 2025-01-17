import tkinter as tk
import os
import encrypt as e
import decrypt as d
import threading as thread
import Key as k
from tkinter import filedialog as fd
from tkinter import ttk

class MainApplication:
    def __init__(self, app, key):
        self.app = app
        self.app.geometry('%sx%s' % (int(self.app.winfo_screenwidth()/2.9), int(app.winfo_screenheight()/2.5)))
        self.app.resizable(width=True, height=True)
        self.listFilenames = []

        self.choose_label_text = tk.StringVar()
        self.choose_label_text.set("Выберите изображение для шифровки:")
        self.encrypt_text = tk.StringVar()
        self.encrypt_text.set("Зашифровать")
        self.HowTo_label_text = tk.StringVar()
        self.HowTo_label_text.set("Выберите способ шифрования:")
        self.app.title("Image "+self.encrypt_text.get()+"- EncryptionTool")

        #Mode
        self.selection_value = tk.IntVar()
        self.selection_value.set(1)
        self.mode_label = tk.Label(self.app, text="Выберите режим:", font=('Helvetica', 9))
        self.mode_radio_e = tk.Radiobutton(self.app, text="Шифрование", variable=self.selection_value, value=1, command=self.selection)
        self.mode_radio_d = tk.Radiobutton(self.app, text="Дешифрование", variable=self.selection_value, value=2, command=self.selection)

        #Способ
        self.howTo_label = tk.Label(self.app, textvariable=self.HowTo_label_text, font=('Helvetica', 9))
        self.encryption_methods = ('Arcfour', 'CAST5', 'ChaCha20', 'GOST28147', 'DES', 'Blowfish', 'AES', 
                                   'Salsa20', 'Twofish', 'Camellia', 'SEED')
        self.selected_method = tk.StringVar()
        self.method_combobox = ttk.Combobox(self.app, textvariable=self.selected_method, state='readonly')
        self.method_combobox['values'] = self.encryption_methods
        self.method_combobox.current(0)

        # Привязка обработчика для изменения метода
        self.method_combobox.bind("<<ComboboxSelected>>", self.method_changed)


        #Choose
        self.choose_label = tk.Label(self.app, textvariable=self.choose_label_text, font=('Helvetica', 10))
        self.choose_entry = tk.Text(self.app, width=0, height=0)
        self.choose_entry.config(state=tk.DISABLED)
        self.add_button = tk.Button(self.app, text ="Добавить", command=self.chooseImg)
        self.clear_button = tk.Button(self.app, text ="Очистить", command=lambda:[self.choose_entry.config(state=tk.NORMAL), self.choose_entry.delete(1.0, tk.END), self.choose_entry.config(state=tk.DISABLED), self.listFilenames.clear()])

        #Output
        self.output_label = tk.Label(self.app, text="Выберите путь сохранения", font=('Helvetica', 10))
        self.output_entry = tk.Entry(self.app)
        self.output_entry.config(state=tk.DISABLED)
        self.output_button = tk.Button(self.app, text="Выберите папку", command=lambda: self.chooseDestination(self.output_entry))

        #Кубик ключ
        self.rubik_key_label = tk.Label(self.app, text="Выберите путь сохранения ключа:", font=('Helvetica',10))
        self.rubik_key_entry = tk.Entry(self.app)
        self.rubik_key_entry.config(state=tk.DISABLED)
        self.rubik_key_output_button = tk.Button(self.app, text="Выберите папку", command=lambda: self.chooseDestination(self.rubik_key_entry))

        #Affine ключики
        self.affine_key_label_a = tk.Label(self.app, text="Введите мультипликативный коэффициент a(должен быть взаимнопростым с 256): ")
        self.affine_key_entry_a = tk.Entry(self.app, width=0)
        self.affine_key_label_b = tk.Label(self.app, text="Введите сдвиг b: ")
        self.affine_key_entry_b = tk.Entry(self.app, width=0)


        #Key
        self.private_key_label = tk.Label(self.app, text="Ваш private key: ", font=('Helvetica', 10))
        self.private_key_entry = tk.Entry(app, width=0)
        self.private_key_entry.insert(0, key)
        self.private_key_entry.config(state=tk.DISABLED)
        self.key_label_text = tk.StringVar()
        self.key_label_text.set("Получателя public key: ")
        self.public_key_label = tk.Label(self.app, textvariable=self.key_label_text, font=('Helvetica', 10))
        self.public_key_entry = tk.Entry(app, width=0)

        #Progress
        self.progressText = tk.StringVar()
        self.progress_label = tk.Label(self.app, textvariable=self.progressText, font=('Helvetica', 9))
        
        #Encrypt
        self.encrypt_button = tk.Button(self.app, textvariable=self.encrypt_text, command= lambda: thread._start_new_thread(self.beginEncryption, (self.listFilenames, key, self.public_key_entry.get())))
        
        #Grid
        self.app.grid_columnconfigure(2, weight=1)
        self.app.grid_rowconfigure(3, weight=1)

        self.mode_label.grid(row=0, column=0, padx=(8,0), pady=(10,5), sticky='wn')
        self.mode_radio_e.grid(row=0, column=1, padx=(4,0), pady=(10,0), sticky='wn')
        self.mode_radio_d.grid(row=0, column=2, padx=(4,0), pady=(10,0), sticky='wn')

        self.howTo_label.grid(row=1, column=0, padx=(8,0), pady=(10,5), sticky='wn', columnspan=3, rowspan=2)
        self.method_combobox.grid(row=1,column=2,padx=(8,0), pady=(10,5),sticky='wn', columnspan=1)

        self.choose_label.grid(row=3, column=0, padx=(8,0), pady=(10,5), sticky='wn', columnspan=3)
        self.choose_entry.grid(row=5, column=0, sticky='wens', padx=(10,5), rowspan=3, columnspan=3)
        self.add_button.grid(row=7, column=3, sticky='wen', padx=(5,10))
        self.clear_button.grid(row=5, column=3, sticky='wes', padx=(5,10), pady=(5,0))
        
        self.output_label.grid(row=9, column=0, padx=(8,0), pady=(10,5), sticky='wn', columnspan=3)
        self.output_entry.grid(row=10, column=0, sticky='wen', padx=(10,5), columnspan=3)
        self.output_button.grid(row=10, column=3, sticky='wen', padx=(5,10))

        self.private_key_label.grid(row=11, column=0, padx=(8,0), pady=(5,5), sticky='wn', columnspan=3)
        self.private_key_entry.grid(row=12, column=0, sticky='wen', padx=10, columnspan=4)
        self.public_key_label.grid(row=13, column=0, padx=(8,0), pady=(5,5), sticky='wn', columnspan=3)
        self.public_key_entry.grid(row=14, column=0, sticky='wen', padx=10, columnspan=4)

        
        self.progress_label.grid(row=17, column=0, sticky='swn', padx=(7,0), pady=(20,10), columnspan=3)

        self.encrypt_button.grid(row=17, column=3, sticky='senw', padx=(0,10), pady=(20,10))

    def method_changed(self, event):
        # Очистить текущие поля
        self.public_key_label.grid_forget()
        self.public_key_entry.grid_forget()
        self.rubik_key_label.grid_forget()
        self.rubik_key_entry.grid_forget()
        self.rubik_key_output_button.grid_forget()
        self.affine_key_label_a.grid_forget()
        self.affine_key_entry_a.grid_forget()
        self.affine_key_label_b.grid_forget()
        self.affine_key_entry_b.grid_forget()
        
        # Отобразить соответствующие поля
        if self.method_combobox.get() == 'Rubik-AES':
            self.rubik_key_label.grid(row=14, column=0, padx=(8, 0), pady=(5, 5), sticky='wn', columnspan=3)
            self.rubik_key_entry.grid(row=15, column=0, sticky='wen', padx=(10, 5), columnspan=3)
            self.rubik_key_output_button.grid(row=15, column=3, sticky='wen', padx=(5,10))
        elif self.method_combobox.get() == 'Affine':
            self.affine_key_label_a.grid(row=13, column=0, padx=(8, 0), pady=(5, 5), sticky='wn', columnspan=3)
            self.affine_key_entry_a.grid(row=14, column=0, sticky='wen', padx=(10, 10), columnspan=3)
            self.affine_key_label_b.grid(row=15, column=0, padx=(8, 0), pady=(5, 5), sticky='wn', columnspan=3)
            self.affine_key_entry_b.grid(row=16, column=0, sticky='wen', padx=(10, 10), columnspan=3)
        else:
            self.public_key_label.grid(row=13, column=0, padx=(8, 0), pady=(5, 5), sticky='wn', columnspan=3)
            self.public_key_entry.grid(row=14, column=0, sticky='wen', padx=10, columnspan=4)


    def selection(self):
        if self.selection_value.get() == 1:
            self.choose_label_text.set("Выберите изображение для шифрации")
            self.encrypt_text.set("Зашифровать")
            self.key_label_text.set("Получателя public key: ")
        else:
            self.choose_label_text.set("Выберите изображение для шифрации")
            self.encrypt_text.set("Расшифровать")
            self.key_label_text.set("Получателя public key: ")

    def chooseImg(self):
        filename = fd.askopenfilenames(title='Выберите изображение')
        for i in filename:
            self.listFilenames.append(i)
            self.choose_entry.config(state=tk.NORMAL)
            self.choose_entry.insert(tk.INSERT, i+'\n')
            self.choose_entry.config(state=tk.DISABLED)

    def chooseDestination(self, target_entry):
        directory = fd.askdirectory(title="Выберите папку")
        if directory:
            target_entry.config(state=tk.NORMAL)
            target_entry.delete(0, tk.END)
            target_entry.insert(0, directory)
            target_entry.config(state=tk.DISABLED)

    #def chooseDestination(self):
    #    path = fd.askdirectory(title='Выберите путь сохранения')
    #   self.output_entry.config(state=tk.NORMAL)
    #    self.output_entry.delete(0, tk.END)
    #    self.output_entry.insert(tk.INSERT, path)
    #    self.output_entry.config(state=tk.DISABLED)

    def beginEncryption(self, listFilenames, private_key, public_key):
        if(self.method_combobox.get() == 'Rubik-AES' or self.method_combobox.get() == 'Affine'):
            public_key = 123
        key = k.Key(private_key, public_key)
        self.changeButtonState(tk.DISABLED)
        self.changeTextBoxState(tk.DISABLED)
        for i in listFilenames:
            self.showBar(i, listFilenames.index(i), len(listFilenames))
            if self.selection_value.get() == 1:
                e.encrypt(i, self.output_entry.get(),self.method_combobox.get(), key, 
                          self.rubik_key_entry.get(), self.affine_key_entry_a.get(), self.affine_key_entry_b.get())
            if self.selection_value.get() == 2:
                d.decrypt(i, self.output_entry.get(), key, self.method_combobox.get(), self.rubik_key_entry.get(),
                          self.affine_key_entry_a.get(), self.affine_key_entry_b.get())
        self.progressText.set(self.encrypt_text.get()+" завершенно. ("+str(len(listFilenames))+"/"+str(len(listFilenames))+")")
        self.clearAllText()
        self.changeButtonState(tk.NORMAL)

    def showBar(self, filename, index, length):
        self.progressText.set(self.encrypt_text.get()+os.path.basename(filename)+" ("+str(index)+"/"+str(length)+")")
        self.app.update_idletasks()

    def changeButtonState(self, s):
        self.add_button.config(state=s)
        self.clear_button.config(state=s)
        self.output_button.config(state=s)
        self.encrypt_button.config(state=s)

    def changeTextBoxState(self, s):
        self.output_entry.config(state=s)
        self.choose_entry.config(state=s)
        self.public_key_entry.config(state=s)

    def clearAllText(self):
        self.changeTextBoxState(tk.NORMAL)
        self.listFilenames.clear()
        self.choose_entry.delete(1.0, tk.END)
        self.output_entry.delete(0, tk.END)
        self.public_key_entry.delete(0,tk.END)
        self.changeTextBoxState(tk.DISABLED)
        self.public_key_entry.config(state=tk.NORMAL)

# class IntroApplication:
#     def __init__(self, app, key):
#         self.app = app
#         self.btn_encrypt = tk.Button(self.app, text="Encrypt", command=lambda:self.start_main('e', key))
#         self.btn_encrypt.pack()
#         self.btn_decrypt = tk.Button(self.app, text="Decrypt", command=lambda:self.start_main('d', key))
#         self.btn_decrypt.pack()
    
#     def start_main(self, flag, key):
#         self.app.destroy()
#         new_app = tk.Tk()
#         main_app = MainApplication(new_app, flag, key)
#         new_app.mainloop()
        
class LoginApp:
    def __init__(self, app):
        self.app = app
        self.app.geometry('%sx%s' % (int(self.app.winfo_screenwidth()/4), int(app.winfo_screenheight()/3)))
        self.app.resizable(width=False, height=False)
        self.app.title("Login - EncryptionTool")
        self.frame = tk.Frame(self.app)

        self.login_label = tk.Label(self.frame, text="Login с помощью private key", font=('Helvetica', 10, 'bold'))
        self.login_entry = tk.Entry(self.frame)
        self.login_button = tk.Button(self.frame, text="Login", font=('Helvetica', 9), command=lambda:self.start_intro(self.login_entry.get()))
        self.generate_button = tk.Button(self.frame, text="Сгенерировать новую пару ключей", font=('Helvetica', 8), command=self.generateKeyPairs)

        self.login_label.grid(pady=(0,8))
        self.login_entry.grid(pady=(0,5), sticky='enw')
        self.login_button.grid(pady=(5,5), ipadx=5, sticky='enw')
        self.generate_button.grid(pady=(5,0), sticky='enw')

        self.frame.place(relx=.5, rely=.5, anchor="c")

    def generateKeyPairs(self):
        files = [('Text Document', '*.txt')]
        f = fd.asksaveasfile(title = "Выберите папку", initialfile='keypairs', filetypes=files, defaultextension=files)
        if f is None:
            return
        [private, public] = k.genKeyPairs()
        text = "private_key = "+str(private)+"\npublic_key = "+str(public)
        f.write(text)
        f.close()

    def start_intro(self, key):
        self.app.destroy()
        new_app = tk.Tk()
        main_app = MainApplication(new_app, key)
        new_app.mainloop()

app = tk.Tk()
login_app = LoginApp(app)
app.mainloop()