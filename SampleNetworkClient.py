import matplotlib.pyplot as plt
import matplotlib.animation as animation
import time
import math
import socket
import os

# Added libraries for encryption / decryption functions
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

class SimpleNetworkClient :
    def __init__(self, port1, port2) :
        self.fig, self.ax = plt.subplots()
        now = time.time()
        self.lastTime = now
        self.times = [time.strftime("%H:%M:%S", time.localtime(now-i)) for i in range(30, 0, -1)]
        self.infTemps = [0]*30
        self.incTemps = [0]*30
        self.infLn, = plt.plot(range(30), self.infTemps, label="Infant Temperature")
        self.incLn, = plt.plot(range(30), self.incTemps, label="Incubator Temperature")
        plt.xticks(range(30), self.times, rotation=45)
        plt.ylim((20,50))
        plt.legend(handles=[self.infLn, self.incLn])
        self.infPort = port1
        self.incPort = port2

        self.infToken = None
        self.incToken = None

        self.ani = animation.FuncAnimation(self.fig, self.updateInfTemp, interval=500)
        self.ani2 = animation.FuncAnimation(self.fig, self.updateIncTemp, interval=500)

        self.block_size = len(os.environ['AES_IV'])

    def enc_recvfrom(self, s, num_bytes):
        aes_object = AES.new(os.environ['AES_KEY'].encode(), AES.MODE_CBC, os.environ['AES_IV'].encode())
        msg, addr = s.recvfrom(num_bytes)
        msg = unpad(aes_object.decrypt(msg), self.block_size)
        return msg, addr
    
    def enc_sendto(self, s, msg, addr):
        aes_object = AES.new(os.environ['AES_KEY'].encode(), AES.MODE_CBC, os.environ['AES_IV'].encode())
        msg = aes_object.encrypt(pad(msg, self.block_size))
        return s.sendto(msg, addr)

    def updateTime(self) :
        now = time.time()
        if math.floor(now) > math.floor(self.lastTime) :
            t = time.strftime("%H:%M:%S", time.localtime(now))
            self.times.append(t)
            #last 30 seconds of of data
            self.times = self.times[-30:]
            self.lastTime = now
            plt.xticks(range(30), self.times,rotation = 45)
            plt.title(time.strftime("%A, %Y-%m-%d", time.localtime(now)))

    def getTemperatureFromPort(self, p, tok) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.enc_sendto(s, b"%s;GET_TEMP" % tok, ("127.0.0.1", p))
        msg, addr = self.enc_recvfrom(s, 1024)
        m = msg.decode("utf-8")
        m = m.split(' ')
        temperature = float(m[0].strip())
        unit_of_measure = m[1].strip()
        return (temperature, unit_of_measure)

    def authenticate(self, p, pw) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.enc_sendto(s, b"AUTH %s" % pw, ("127.0.0.1", p))
        msg, addr = self.enc_recvfrom(s, 1024)
        return msg.strip()

    def processInfTemp(self):
        temperature_set = self.getTemperatureFromPort(self.infPort, self.infToken)
        temperature = temperature_set[0]
        unit_of_measure = temperature_set[1]

        if unit_of_measure == 'C':
            return temperature
        if unit_of_measure == 'F':
            return (temperature - 32) / 1.800
        return temperature - 273

    def updateInfTemp(self, frame) :
        self.updateTime()
        if self.infToken is None : #not yet authenticated
            self.infToken = self.authenticate(self.infPort, b"%s" % os.environ['PRE_SHARED_KEY'].encode())

        self.infTemps.append(self.processInfTemp())
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,

    def processIncTemp(self):
        temperature_set = self.getTemperatureFromPort(self.incPort, self.incToken)
        temperature = temperature_set[0]
        unit_of_measure = temperature_set[1]

        if unit_of_measure == 'C':
            return temperature
        if unit_of_measure == 'F':
            return (temperature - 32) / 1.800
        return temperature - 273

    def updateIncTemp(self, frame) :
        self.updateTime()
        if self.incToken is None : #not yet authenticated
            self.incToken = self.authenticate(self.incPort, b"%s" % os.environ['PRE_SHARED_KEY'].encode())

        self.incTemps.append(self.processIncTemp())
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,

snc = SimpleNetworkClient(23456, 23457)

plt.grid()
plt.show()
