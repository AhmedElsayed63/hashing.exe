import tkinter as tk
from tkinter import messagebox, scrolledtext
import hashlib, binascii, pyperclip

# ====== دوال الهاش ======
def generate_hash():
    text = input_box.get("1.0", tk.END).strip()
    algo = algo_var.get()
    if not text:
        messagebox.showinfo("Info", "اكتب نص علشان نحسب الهاش")
        return

    try:
        if algo == "CRC32":
            result = format(binascii.crc32(text.encode('utf-8')) & 0xffffffff, '08X')
        elif algo == "Adler32":
            result = format(binascii.adler32(text.encode('utf-8')) & 0xffffffff, '08X')
        else:
            hash_func = hashlib.new(algo.lower())
            hash_func.update(text.encode('utf-8'))
            result = hash_func.hexdigest()
    except Exception:
        result = "⚠️ Algorithm not supported"

    output_box.config(state='normal')
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, result)
    output_box.config(state='disabled')

def copy_hash():
    result = output_box.get("1.0", tk.END).strip()
    if result:
        pyperclip.copy(result)
        messagebox.showinfo("Copied", "تم نسخ الهاش إلى الحافظة ✅")

# ====== واجهة البرنامج ======
root = tk.Tk()
root.title("Hash Generator | CRC, SHA, MD, RIPEMD")
root.geometry("700x600")
root.configure(bg="#E6E6E6")

title = tk.Label(root, text="Data Integrity & Hash Generator",
                 fg="#0047AB", bg="#E6E6E6",
                 font=("Segoe UI", 18, "bold"))
title.pack(pady=20)

# نص الإدخال
tk.Label(root, text="Enter Data:", fg="black", bg="#E6E6E6", font=("Segoe UI", 12)).pack()
input_box = scrolledtext.ScrolledText(root, height=6, width=70,
                                      bg="#F8F8F8", fg="black", font=("Consolas", 11))
input_box.pack(pady=10)

# اختيار الخوارزمية
frame_algo = tk.Frame(root, bg="#E6E6E6")
frame_algo.pack(pady=10)
tk.Label(frame_algo, text="Select Algorithm:", fg="black", bg="#E6E6E6",
         font=("Segoe UI", 12)).pack(side=tk.LEFT, padx=5)

supported_algos = sorted(list(hashlib.algorithms_available))
# إضافة خوارزميات إضافية
supported_algos += ["CRC32", "Adler32"]

algo_var = tk.StringVar(value="SHA256")
algo_menu = tk.OptionMenu(frame_algo, algo_var, *supported_algos)
algo_menu.config(bg="#007BFF", fg="white", font=("Segoe UI", 11, "bold"), width=15)
algo_menu.pack(side=tk.LEFT, padx=10)

# زر التوليد
tk.Button(root, text="Generate Hash", command=generate_hash,
          bg="#007BFF", fg="white", font=("Segoe UI", 12, "bold"),
          width=20, height=1).pack(pady=15)

# النتيجة
tk.Label(root, text="Hash Result:", fg="black", bg="#E6E6E6",
         font=("Segoe UI", 12)).pack()
output_box = scrolledtext.ScrolledText(root, height=4, width=70,
                                       bg="#F8F8F8", fg="#0047AB",
                                       font=("Consolas", 11), state='disabled')
output_box.pack(pady=10)

# زر النسخ
tk.Button(root, text="Copy Hash", command=copy_hash,
          bg="#007BFF", fg="white", font=("Segoe UI", 11, "bold"),
          width=15).pack(pady=5)

# النص السفلي
tk.Label(root, text="Supervised by Eng. Mohamed Ezzat",
         fg="#444444", bg="#E6E6E6",
         font=("Segoe UI", 10, "italic")).pack(side="bottom", pady=15)

root.mainloop()
