import tkinter as tk

class NumberBoard:
    def __init__(self, number = None):
        self.root = tk.Tk()
        self.root.title("Number Board")
        self.canvas = tk.Canvas(self.root, width=1024, height=50)
        self.canvas.bind("<Button-1>", lambda event: self.handle_click(event))
        self.canvas.pack()

        self.frame1 = tk.Frame(self.root)
        
        self.binary_label = tk.Label(self.frame1, text="Binary:", font=("Arial", 8))
        self.binary_label.pack()
        self.hex_label = tk.Label(self.frame1, text="Hexadecimal:", font=("Arial", 8))
        self.hex_label.pack()
        self.decimal_label = tk.Label(self.frame1, text="Decimal:", font=("Arial", 8))
        self.decimal_label.pack()
        self.octal_label = tk.Label(self.frame1, text="Octal:", font=("Arial", 8))
        self.octal_label.pack()
        
        self.frame1.pack(side=tk.LEFT, padx=10)
        self.frame2 = tk.Frame(self.root)

        self.size_label = tk.Label(self.frame2, text="Size:", font=("Arial", 8))
        self.size_label.pack()
        self.kb_label = tk.Label(self.frame2, text="KB:", font=("Arial", 8))
        self.kb_label.pack()
        self.mb_label = tk.Label(self.frame2, text="MB:", font=("Arial", 8))
        self.mb_label.pack()
        self.gb_label = tk.Label(self.frame2, text="GB:", font=("Arial", 8))
        self.gb_label.pack()
        self.tb_label = tk.Label(self.frame2, text="TB:", font=("Arial", 8))
        self.tb_label.pack()
        self.frame2.pack(side=tk.LEFT, padx=10)




        
        self.textbox = tk.Entry(self.root)
        if number is None:
            number = "0x00000000"
        self.textbox.insert(0, number)

        self.textbox.bind("<Return>", lambda event: self.draw_board())

        
        self.textbox.pack()

        self.button = tk.Button(self.root, text="Show Number", command=self.draw_board)
        self.button.pack()
        
        self.draw_board()

        self.root.mainloop()

    def get_bits(self, number):
        bits = []
        for i in range(63, -1, -1):
            bits.append((number >> i) & 1)
        return bits

    def draw_board(self):
        text = self.textbox.get()
        if text.startswith("0x"):
            number = int(text, 16)
        else:
            number = int(text)
        bits = self.get_bits(number)
        for i in range(64):
            x = i * 16 + 10
            y = 10
            self.canvas.create_text(x, y, text=str(63-i), font=("Arial", 8))
            if bits[i] == 1:
                self.canvas.create_rectangle(x - 5, y + 5, x + 5, y + 15, fill="black")
            else:
                self.canvas.create_rectangle(x - 5, y + 5, x + 5, y + 15, fill="white")
        self.binary_label.config(text="Binary: {}".format(bin(number)[2:]))
        self.hex_label.config(text="Hexadecimal: {}".format(hex(number)[2:]))
        self.decimal_label.config(text="Decimal: {}".format(number))
        self.octal_label.config(text="Octal: {}".format(oct(number)[2:]))

        self.size_label.config(text="Size:")
        self.kb_label.config(text="KB: {}".format(number/1024))
        self.mb_label.config(text="MB: {}".format(number/1024**2))
        self.gb_label.config(text="GB: {}".format(number/1024**3))
        self.tb_label.config(text="TB: {}".format(number/1024**4))

        

    def flip_bit(self, bit_index):
        mask = 1 << bit_index
        text = self.textbox.get()
        if text.startswith("0x"):
            number = int(text, 16)
        else:
            number = int(text)
        number ^= mask
        
        self.textbox.delete(0, tk.END)
        self.textbox.insert(0, hex(number))
        self.draw_board()

    def handle_click(self, event):
        x = event.x
        y = event.y
        for i in range(64):
            rect_x = i * 16 + 5
            rect_y = 5
            if rect_x <= x <= rect_x + 10 and rect_y <= y <= rect_y + 10 + 5 + 15:
                self.flip_bit(63-i)
                break
        

        




if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        nb = NumberBoard(sys.argv[1])
    else:
        nb = NumberBoard()

