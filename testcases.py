from sys import exit
import socket
from time import sleep


def authenticate(port, password):
    """
    Authentication function used in all testcases to authenticate with server
    """
    s = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)
    s.sendto(b"AUTH %s" % password, ("127.0.0.1", port))
    msg, addr = s.recvfrom(1024)
    return (s, msg.strip())


def testcase1():
    """
    Vulnerabilty 1 is incorrect display of informaiton on client side
    using simple client in SampleNetworkClient.py
    1) Testcase will authentication to receive a token.
    2) Testcase will SET_DEGF on infant port.
    3) Testcase will SET_DEGC on incubator port.
    4) View Plot as temperatures for both will plummet below the 20 axis.
    """
    try:
        inf_port = 23456
        (inf_socket, inf_token) = authenticate(inf_port, b"!Q#E%T&U8i6y4r2w")
        
        # SET_DEGF on infant port
        inf_socket.sendto(b"%s;SET_DEGF" % inf_token, ("127.0.0.1", inf_port))

        sleep(5)
        
        # SET_DEGC on infant port
        inf_socket.sendto(b"%s;SET_DEGC" % inf_token, ("127.0.0.1", inf_port))

        assert(inf_token != None)
    except Exception as ex:
        print (ex)
        assert(1 == 2)


def testcase2():
    """
    Vulnerabilty 2 is incorrect display of informaiton on client side
    using the client defined in SampleNetworkClient.py
    1) Make sure SampleNetworkClient.py is running alongside SampleNetworkClient.py
    1) Testcase will authentication to receive a token.
    2) Testcase will SET_DEGF on infant port.
    3) Testcase will SET_DEGC on incubator port.
    4) View Plot as temperatures for both will plummet below the 20 axis.
    """
    try:
        inf_port = 23456
        (inf_socket, inf_token) = authenticate(inf_port, b"!Q#E%T&U8i6y4r2w")
        
        # SET_DEGF on infant port
        inf_socket.sendto(b"%s;SET_DEGF" % inf_token, ("127.0.0.1", inf_port))
        
        sleep(5)

        # SET_DEGC on incubator port
        inf_socket.sendto(b"%s;SET_DEGC" % inf_token, ("127.0.0.1", inf_port))

        assert(inf_token != None)
    except Exception as ex:
        print (ex)
        assert(1 == 2)


def testcase3():
    """
    Vulnerability 3 is ability to delete a session token without need for PSK
    1) Testcase will authenticate to generate a token
    2) Testcase will then attempt to delete said token without use of PSK
    3) Testcase will then attempt an action with token to see if token was succesfully deleted
    """
    try:
        inf_port = 23456
        
        (inf_socket, inf_token) = authenticate(inf_port, b"!Q#E%T&U8i6y4r2w")

        # Kill session
        inf_socket.sendto(b"LOGOUT %s" % inf_token, ("127.0.0.1", inf_port))

        # Attempt SET_DEGF
        inf_socket.sendto(b"%s;GET_TEMP" % inf_token, ("127.0.0.1", inf_port))
        msg, addr = inf_socket.recvfrom(1024)
        
        assert_message = msg.strip()

        assert(assert_message != 'BAD TOKEN')
    except Exception as ex:
        print (ex)
        assert(1 == 2)


def testcase4():
    """
    Vulnerability 4 is hardcoded credentials in the server code
    1) Testcase will open file SampleNetworkServer.py
    2) Testcase will then read line by line to check for the hardcoded password
    """
    try:
        file_handler = open('./SampleNetworkServer.py')
        for line in file_handler:
            assert('!Q#E%T&U8i6y4r2w' not in line)
    except Exception as ex:
        print (ex)
        assert(1 == 2)


def testcase5():
    """
    Vulnerability 5 is hardcoded credentials in the client code
    1) Testcase will open file SampleNetworkClient.py
    2) Testcase will then read line by line to check for the hardcoded password
    """
    try:
        file_handler = open('./SampleNetworkClient.py')
        for line in file_handler:
            assert('!Q#E%T&U8i6y4r2w' not in line)
    except Exception as ex:
        print (ex)
        assert(1 == 2)

def testcase6():
    """
    Vulnerability 6 and 7 are authentication token and authentication
    credentials sent in plaintext.
    1) Open wireshark and listen on localhost to check for plaintext auth token
    2) Testcase will authenticate to receive a token
    """
    try:
        
        inf_port = 23456
        inc_port = 23457
        inc_token = authenticate(inc_port, b"!Q#E%T&U8i6y4r2w")[1]

        # SampleNetworkServer has authentication so the testcase will exit at this assertion.
        assert(inc_token != None)
    except Exception as ex:
        print (ex)
        assert(1 == 2)
        

def main():
    testcases = {
        '1': testcase1,
        '2': testcase2,
        '3': testcase3,
        '4': testcase4,
        '5': testcase5,
        '6': testcase6,
        'exit': exit
    }

    while True:
        print(f'Available options for input: {[x for x in testcases]}')
        key = input('Which testcase would you like to try?:\n')
        if key in testcases:
            testcases.get(key)()


if __name__ == '__main__':
    main()
