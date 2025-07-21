from tkinter import Toplevel, Label

def create_tooltip(widget, text):
    def on_enter(e):
        top = Toplevel(widget)
        top.wm_overrideredirect(True)
        top.geometry(f"+{e.x_root+10}+{e.y_root+10}")
        label = Label(top, text=text, bg="yellow", font=("Segoe UI", 10))
        label.pack()
        widget.tooltip = top

    def on_leave(e):
        if hasattr(widget, 'tooltip'):
            widget.tooltip.destroy()

    widget.bind("<Enter>", on_enter)
    widget.bind("<Leave>", on_leave) 