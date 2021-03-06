# -*- coding: utf-8 -*-

from Tkinter import *
import time, threading

def show_sp1():
	log_file = open('log_1.txt')
	sp = log_file.readline()
	while sp != '':
		print sp[:-1] + 'KB/s'
		msg1_speed.set(sp[:-1] + 'KB/s')
		time.sleep(0.5)
		sp = log_file.readline()
		if not ifrun.isSet():
			msg1_speed.set('0KB/s')
			break
def show_sp2():
	log_file = open('log_2.txt')
	sp = log_file.readline()
	while sp != '':
		print sp[:-1] + 'KB/s'
		msg2_speed.set(sp[:-1] + 'KB/s')
		time.sleep(0.5)
		sp = log_file.readline()
		if not ifrun.isSet():
			msg2_speed.set('0KB/s')
			break
def start_func():
	global th1, th2
	global ifrun
	th1 = threading.Thread(target = show_sp1)
	th2 = threading.Thread(target = show_sp2)
	ifrun = threading.Event()
	ifrun.set()
	th1.setDaemon(True) # 守护进程
	th1.start()
	th2.setDaemon(True) # 守护进程
	th2.start()

def stop_func():
	ifrun.clear()

top = Tk()
top.title('RaptorQ')
top.geometry('1000x500+500+300')
w = Canvas(top, width=1000, height=500, bg='white') 
w.grid(row=0, column=0, rowspan=4, columnspan=2) 
btn_start = Button(top, text = 'Start', command = start_func, width = 10, font = ('Arial, 18'))
btn_stop = Button(top, text = 'Stop', command = stop_func, width = 10, font = ('Arial, 18'))
msg1_speed = StringVar()
msg2_speed = StringVar()
label1_speed = Label(top, textvariable = msg1_speed, width = 15, font = ('Arial, 20'), bg = 'white')
label2_speed = Label(top, textvariable = msg2_speed, width = 15, font = ('Arial, 20'), bg = 'white')
msg1_speed.set('0KB/s')
msg2_speed.set('0KB/s')

btn_start.grid(row = 1, column = 1)
btn_stop.grid(row = 2, column = 1)
label1_speed.grid(row = 1, column = 0)
label2_speed.grid(row = 2, column = 0)
mainloop()
