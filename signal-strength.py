#!/usr/bin/env python3
from scapy.all import *
import tkinter as tk
import sys

def ph(pkt):
  global MAC
  global SSID
  global Signal
  global ssid
  global signal
  if pkt.haslayer(Dot11):
    if pkt.type == 0 and pkt.subtype == 8:
      MAC = pkt.addr2
      SSID = pkt.info
      Signal = pkt.dBm_AntSignal
      if mac == MAC:
        ssid = SSID
        signal = Signal

if len(sys.argv) < 3:
  print("syntax : signal-strength <interface> <mac>")
  print("sample : signal-strength mon0 00:11:22:33:44:55")
iface = sys.argv[1]
mac = sys.argv[2]

def reload():
  global window
  global label
  global mac
  global signal
  window.after(100, reload)
  window.title(ssid)

  string = "%s\nsignal strength : %d" % (mac, signal)
  label.config(text = string)

  sniff(iface=iface, prn=ph, count=1)

window=tk.Tk()
window.after(100, reload)

ssid = str(mac)
signal = -100

window.title(ssid)
window.geometry("150x50")
window.resizable(False, False)

string = "%s\nsignal strength : %d" % (mac, signal)
label=tk.Label(window, text=string)
label.pack()

window.mainloop()
