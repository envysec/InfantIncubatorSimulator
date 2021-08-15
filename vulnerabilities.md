# Vulnerabilities - Testcases, Vulnerabilities, Patches

## Notes for testing
Please make sure you export the necessary variables/secrets to run the client as hard coded secrets have been removed for security purposes. In this case you want to set the value variables:

- PRE_SHARED_KEY = [AUTH CREDENTIALS]
- AES_KEY = [32 BYTE KEY]
- AES_IV = [16 BYTE IV]

Make sure that both SampleNetworkServer.py and SampleNetworkClient.py are running for Testcases 1, 2, and 6

## 1 - Simple Client does not reflect appropriate values when server switches self.deg to either celsius or fahrenheit

### Description
Initial start up of network server and client will result in display of temperatures on graph based on Celsius values despite server side values being stored as Kelvin. This indicates some transformation occurs on client side to make the graph display appropriately. However, upon execution of SET_DEGF or SET_DEGC, the temperature on the graph will plummet below 20. This is a bug in the code that will result in the output of incorrect information to users - an effect of data integrity loss. This is due to the SimpleClient Object within SampleNetworkServer.py interpreting all data received as Kelvin.

### Test
See testcase1() in testcases.py

### Patch
SimpleClient Object must have its ```self.infTherm.getTemperature() - 273``` hardcoded calculation removed. Instead a new method call processInfTemp() is introduced to take into account what unit of measurement the values being sent from the thermometer is. See code snippet below.

```
def processInfTemp(self):
    if self.infTherm.deg == 'C':
        print(self.infTherm.getTemperature())
        return self.infTherm.getTemperature()
    if self.infTherm.deg == 'F':
        print(self.infTherm.getTemperature())
        return (self.infTherm.getTemperature() - 32) / 1.800
    return self.infTherm.getTemperature() - 273

def updateInfTemp(self, frame) :
    self.updateTime()
    self.infTemps.append(self.processInfTemp())
    #self.infTemps.append(self.infTemps[-1] + 1)
    self.infTemps = self.infTemps[-30:]
    self.infLn.set_data(range(30), self.infTemps)
    return self.infLn,
```

## 2 - Simple Network Client does not reflect appropriate values when server switches self.deg to either celsius or farenheit

### Description
Initial start up of network server and network client will result in display of temperatures on graph based on celsius values despite server side values being stored as Kelvin. This indicates some transformation occurs on client side to make the graph display appropriately. However, upon execution of SET_DEGF or SET_DEGC, the temperature on the graph will plummet below 20. This is a bug in the code that will result in the output of incorrect informatino to users - an effect of data integrity loss. This is due to the SimpleNetworkClient Object within SampleClientServer.py interpreting all data as Kelvin

### Test
See testcase2() in testcases.py

### Patch
There are 3 parts to succesfully patch this bug:
1) Update server code to return temperature as well as a unit of measurement when processing a get_temperature() request to provide context to the numerical value returned.
```
elif c == "GET_TEMP" :
    self.serverSocket.sendto(b"%f %s\n" % (self.getTemperature(), self.deg.encode()), addr)
```
2) Updated network client code to parse server response accordingly to get both temperature and units of measurements.
```
def getTemperatureFromPort(self, p, tok) :
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"%s;GET_TEMP" % tok, ("127.0.0.1", p))
    msg, addr = s.recvfrom(1024)
    m = msg.decode("utf-8")
    m = m.split(' ')
    temperature = float(m[0].strip())
    unit_of_measure = m[1].strip()
    return (temperature, unit_of_measure)
```
3) Removed hardcoded calculation of -273 in updateInfTemp() method. Created a new method processInfTemp() to take units of measurements into account when calculating temperature.
```
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
```

## 3 - Ability to Delete Authorization Tokens Without the Need to Authenticate

### Description
Clients are able to delete authorization tokens using the command ```LOGOUT [AUTH TOKEN]```. This can be done without any other authentication mechanisms in place which means there is a potential for brute forcing to take place to kill existing sessions or this vulnerability can be chained with the fact that the Authentication tokens are transmitted in clear plaintext to employ a denial of service. This bug is found in the SampleNetworkServer.py

### Test
See testcase3() in testcases.py

### Patch
Require the client to authenticate and provide the Preshared Key when logging out. There needs to be an adjustment on how the Logout command is processed (the processCommands() method) and how it is parsed (the run() method). See code snippets below.

```
def processCommands(self, msg, addr) :
    cmds = msg.split(';')
    for c in cmds :
        cs = c.split(' ')
        if len(cs) == 2 : #should be either AUTH
            if cs[0] == "AUTH":
                if cs[1] == os.environ['PRE_SHARED_KEY'] :
                    self.tokens.append(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)))
                    self.serverSocket.sendto(self.tokens[-1].encode("utf-8"), addr)
                    #print (self.tokens[-1])
            else : #unknown command
                self.serverSocket.sendto(b"Invalid Command\n", addr)
        elif len(cs) == 3 : # Should be LOGOUT
            if cs[0] == "LOGOUT" and cs[1] == os.environ['PRE_SHARED_KEY']:
                self.tokens.remove(cs[2])
            else : #unknown command
                self.serverSocket.sendto(b"Invalid Command\n", addr)
```
```
def run(self) : #the running function
    while True : 
        try :
            msg, addr = self.serverSocket.recvfrom(1024)
            msg = msg.decode("utf-8").strip()
            cmds = msg.split(' ')
            if len(cmds) == 1 : # protected commands case
                semi = msg.find(';')
                if semi != -1 : #if we found the semicolon
                    #print (msg)
                    if msg[:semi] in self.tokens : #if its a valid token
                        self.processCommands(msg[semi+1:], addr)
                    else :
                        self.serverSocket.sendto(b"Bad Token\n", addr)
                else :
                        self.serverSocket.sendto(b"Bad Command\n", addr)
            elif len(cmds) == 2 :
                if cmds[0] == 'AUTH' : #if its AUTH
                    self.processCommands(msg, addr) 
                else :
                    self.serverSocket.sendto(b"Authenticate First\n", addr)
            elif len(cmds) == 3 :
                if cmds[0] == 'LOGOUT' :
                    self.processCommands(msg, addr)
                else :
                    self.serverSocket.sendto(b"Authenticate First\n", addr)
            else :
                # otherwise bad command
                self.serverSocket.sendto(b"Bad Command\n", addr)
```

## 4 - Hard Coded Secrets in Server Code

### Description
Credentials should not be hardcoded within source code. This introduces risk of grabbing credentials from binary analysis or just viewing the source code if that is available. Given that this implies all servers use the same hardcoded password that can lead to exploitation across all servers.

### Test
See testcase4() in testcases.py

### Patch
Credentials should be pulled via environmental variables to reduce risk introduced by hard coded secrets. See code snippet below.
```
def processCommands(self, msg, addr) :
    cmds = msg.split(';')
    for c in cmds :
        cs = c.split(' ')
        if len(cs) == 2 : #should be either AUTH
            if cs[0] == "AUTH":
                if cs[1] == os.environ['PRE_SHARED_KEY'] :
                    self.tokens.append(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)))
                    self.serverSocket.sendto(self.tokens[-1].encode("utf-8"), addr)
                    #print (self.tokens[-1])
            else : #unknown command
                self.serverSocket.sendto(b"Invalid Command\n", addr)
        elif len(cs) == 3 : # Should be LOGOUT
            if cs[0] == "LOGOUT" and cs[1] == os.environ['PRE_SHARED_KEY']:
                self.tokens.remove(cs[2])
            else : #unknown command
                self.serverSocket.sendto(b"Invalid Command\n", addr)
```

## 5 - Hard Coded Secrets in Client Code

### Description
Credentials should not be hardcoded within source code. This introduces risk of grabbing credentials from binary analysis or just viewing the source code if that is available. Given that this implies all servers use the same hardcoded password that can lead to exploitation across all servers.

### Test
See testcase5() in testcases.py

### Patch
Credentials should be pulled via environmental variables to reduce risk introduced by hard coded secrets. See code snippet below.
```
def updateInfTemp(self, frame) :
        self.updateTime()
        if self.infToken is None : #not yet authenticated
            self.infToken = self.authenticate(self.infPort, b"%s" % os.environ['PRE_SHARED_KEY'].encode())

        self.infTemps.append(self.processInfTemp())
        #self.infTemps.append(self.infTemps[-1] + 1)
        self.infTemps = self.infTemps[-30:]
        self.infLn.set_data(range(30), self.infTemps)
        return self.infLn,
```
```
    def updateIncTemp(self, frame) :
        self.updateTime()
        if self.incToken is None : #not yet authenticated
            self.incToken = self.authenticate(self.incPort, b"%s" % os.environ['PRE_SHARED_KEY'].encode())

        self.incTemps.append(self.processIncTemp())
        #self.incTemps.append(self.incTemps[-1] + 1)
        self.incTemps = self.incTemps[-30:]
        self.incLn.set_data(range(30), self.incTemps)
        return self.incLn,
```

## 6 - Client Sends Password and Token as Plaintext Over Unencrypted Channel

### Description
Passwords and other login credentials should not be sent in plaintext over the network. This exposes the user to complete account compromise if any packet containing sensistive login information is sniffed by an adversary.

### Test
See testcase6() in testcases.py

### Patch
Credentials should only be sent over encrypted channels to prevent anyone other than the intended recipient from reading them. To facilitate this, the SampleNetworkClient has been patched so that all communications with the server use AES. See code snippet below.
```
    def enc_recvfrom(self, num_bytes):
        aes_object = AES.new(os.environ['AES_KEY'].encode(), AES.MODE_CBC, os.environ['AES_IV'].encode())
        msg, addr = self.serverSocket.recvfrom(num_bytes)
        msg = unpad(aes_object.decrypt(msg), self.block_size)
        return msg, addr
```
```
    def enc_sendto(self, msg, addr):
        aes_object = AES.new(os.environ['AES_KEY'].encode(), AES.MODE_CBC, os.environ['AES_IV'].encode())
        msg = aes_object.encrypt(pad(msg, self.block_size))
        return self.serverSocket.sendto(msg, addr)
```
```
    def authenticate(self, p, pw) :
        s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
        self.enc_sendto(s, b"AUTH %s" % pw, ("127.0.0.1", p))
        msg, addr = self.enc_recvfrom(s, 1024)
        return msg.strip()
```

## 7 - Server Sends Token as Plaintext Over Unencrypted Channel

### Description
Passwords and other login credentials should not be sent in plaintext over the network. This exposes the user to complete account compromise if any packet containing sensistive login information is sniffed by an adversary.

### Test
See testcase6() in testcases.py

### Patch
Credentials should only be sent over encrypted channels to prevent anyone other than the intended recipient from reading them. To facilitate this, the SampleNetworkServer has been patched so that all communications with the client use AES. See code snippet below.
```
    def enc_recvfrom(self, num_bytes):
        aes_object = AES.new(os.environ['AES_KEY'].encode(), AES.MODE_CBC, os.environ['AES_IV'].encode())
        msg, addr = self.serverSocket.recvfrom(num_bytes)
        msg = unpad(aes_object.decrypt(msg), self.block_size)
        return msg, addr
```
```
    def enc_sendto(self, msg, addr):
        aes_object = AES.new(os.environ['AES_KEY'].encode(), AES.MODE_CBC, os.environ['AES_IV'].encode())
        msg = aes_object.encrypt(pad(msg, self.block_size))
        return self.serverSocket.sendto(msg, addr)
```
```
    def processCommands(self, msg, addr) :
        cmds = msg.split(';')
        for c in cmds :
            cs = c.split(' ')
            if len(cs) == 2 : #should be either AUTH
                if cs[0] == "AUTH":
                    if cs[1] == os.environ['PRE_SHARED_KEY'] :
                        self.tokens.append(''.join(random.choice(string.ascii_uppercase + string.ascii_lowercase + string.digits) for _ in range(16)))
                        self.enc_sendto(self.tokens[-1].encode("utf-8"), addr)
                        #print (self.tokens[-1])
                else : #unknown command
                    self.enc_sendto(b"Invalid Command\n", addr)
            elif len(cs) == 3 : # Should be LOGOUT
                if cs[0] == "LOGOUT" and cs[1] == os.environ['PRE_SHARED_KEY']:
                    self.tokens.remove(cs[2])
                else : #unknown command
                    self.enc_sendto(b"Invalid Command\n", addr)
            elif c == "SET_DEGF" :
                self.deg = "F"
            elif c == "SET_DEGC" :
                self.deg = "C"
            elif c == "SET_DEGK" :
                self.deg = "K"
            elif c == "GET_TEMP" :
                self.enc_sendto(b"%f %s\n" % (self.getTemperature(), self.deg.encode()), addr)
            elif c == "UPDATE_TEMP" :
                self.updateTemperature()
            elif c :
                self.enc_sendto(b"Invalid Command\n", addr)
```
