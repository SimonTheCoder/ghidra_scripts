import tkinter as tk

class NumberBoard:
    def __init__(self, number = None):
        self.root = tk.Tk()
        self.root.title("Number Board")
        self.canvas = tk.Canvas(self.root, width=1024, height=50)
        self.canvas.pack()

        self.binary_label = tk.Label(self.root, text="Binary:", font=("Arial", 8))
        self.binary_label.pack()
        self.hex_label = tk.Label(self.root, text="Hexadecimal:", font=("Arial", 8))
        self.hex_label.pack()
        self.decimal_label = tk.Label(self.root, text="Decimal:", font=("Arial", 8))
        self.decimal_label.pack()
        self.octal_label = tk.Label(self.root, text="Octal:", font=("Arial", 8))
        self.octal_label.pack()

        
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
            self.canvas.create_text(x, y, text=str(64-i), font=("Arial", 8))
            if bits[i] == 1:
                self.canvas.create_rectangle(x - 5, y + 5, x + 5, y + 15, fill="black")
            else:
                self.canvas.create_rectangle(x - 5, y + 5, x + 5, y + 15, fill="white")
        self.binary_label.config(text="Binary: {}".format(bin(number)[2:]))
        self.hex_label.config(text="Hexadecimal: {}".format(hex(number)[2:]))
        self.decimal_label.config(text="Decimal: {}".format(number))
        self.octal_label.config(text="Octal: {}".format(oct(number)[2:]))

        

        




if __name__ == "__main__":
    import sys

    if len(sys.argv) > 1:
        nb = NumberBoard(sys.argv[1])
    else:
        nb = NumberBoard()
