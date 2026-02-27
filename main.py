import qrcode
from pyzbar.pyzbar import decode
from PIL import Image
from PIL import ImageTk
from time import sleep
import tkinter as tk
from tkinter import messagebox
from tkinter import filedialog

labels = []
def show_photo(root, place="QR.png"):
    global labels
    size = 150
    # 使用 Pillow 打开图片
    img_open = Image.open(place)
    img_open = img_open.resize((size, size))
    # 将图片转换为 PhotoImage 对象
    img_png = ImageTk.PhotoImage(img_open)
    # 检查是否存在旧的 label 并删除
    if labels:
        old_label, old_img_png = labels[0]
        old_label.destroy()
        labels.clear()
    # 创建一个 Label 对象，并将图片对象传递给它
    label = tk.Label(root, image=img_png)
    # 显示 Label 对象
    label.place(x=120, y=20)
    label.img_png = img_png
    labels.append((label, img_png))  # 存储 label 和 img_png 的引用


def zebra(root):
    global labels
    name = "QR.png"
    content = filedialog.askopenfilename(title="选择文件",
        filetypes=[("文本文件(*.txt)", "*.txt"), ("所有文件", "*.*")])
    try:
        with open(content, 'rb') as f:
            data = f.read()
        # 创建二维码对象(字符串|数字)，文字越多图越复杂
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(data)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        # 保存图片
        img.save(name)
        print('图片已保存在程序同目录下')
        # 调用 show_photo 函数更新显示的二维码图片
        show_photo(root)
    except Exception as e:
        print(f"Error occurred: {e}")


# 解码
def unzebra():
    img = Image.open(filedialog.askopenfilename(title="选择文件",
        filetypes=[("图片文件(*.png)", "*.png"), ("所有文件", "*.*")]))
    result = decode(img)
    print(result[0][0].decode())
    messagebox.showinfo(title="QR", message=result[0][0].decode())

# 版权保护
# noinspection PyUnreachableCode
def error():
    try:
        if unzebras(position='Error.png') != "638867435bc694a5ff1a3132337177656173647a7863":
            print("File Error")
            sleep(3)
            input()
            exit()
    except:
        print("File Error")
        sleep(3)
        input()
        exit()

def about():
    messagebox.showinfo(title="关于", message="powered by liang-rising-star \n 关注仓库进展获取实时更新请访问： \n https://github.com/liang-rising-star/Py-zebra-QR-Code-Generator")

def main():
    #error()
    cmd = ""
    root = tk.Tk()
    root.geometry("300x200")
    root.title("二维码制作")
    menu_bar = tk.Menu(root)
    root.config(menu=menu_bar)
    more_menu = tk.Menu(menu_bar, tearoff=0)
    # menu_bar.add_cascade(label="language", menu=more_menu)
    # more_menu.add_command(label="简体中文")
    # more_menu.add_command(label="English")
    menu_about = root.config(menu=menu_bar)
    menu_bar.add_cascade(label="关于", menu=menu_about, command=about)
    make = (tk.Button(root, text="制作二维码", command=lambda: zebra(root)))
    make.place(x=30, y=50)
    unmake = (tk.Button(root, text="二维码解码", command=unzebra))
    unmake.place(x=30, y=100)
    show_photo(root, place="1st.png")
    root.mainloop()
    # 制作功能保存路径未成功打开文件，工具栏功能未完成，保存时应保存成 txt 文件


if __name__ == '__main__':
    main()