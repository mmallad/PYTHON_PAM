"""
Dpak Malla
mmallad
Plugable Authentication Module For Python
"""

#first import all necessary libarary
#import ctypes

from ctypes import CDLL, CFUNCTYPE, POINTER, Structure, cast, pointer, sizeof
from ctypes import c_char, c_int, c_char_p, c_uint, c_void_p
from ctypes.util import find_library

class Handle(Structure):
    _fields_ = [
        ("handle", c_void_p)
    ]

    def __init__(self):
        Structure.__init__(self)
        self.handle = 0

class Msg(Structure):
    _fields_ = [
        ("msg_style", c_int),
        ("msg", c_char_p),
        ]

    def __repr__(self):
        return "<Message %i '%s'>" % (self.msg_style, self.msg)

class Response(Structure):
    _fields_ = [
        ("resp", c_char_p),
        ("resp_retcode", c_int),
        ]

    def __repr__(self):
        return "<Response %i '%s'>" % (self.resp_retcode, self.resp)

conv_func = CFUNCTYPE(c_int,
    c_int, POINTER(POINTER(Msg)),
    POINTER(POINTER(Response)), c_void_p)


class Conv(Structure):
    _fields_ = [
        ("conv", conv_func),
        ("appdata_ptr", c_void_p)
    ]

class Pam(Structure):
    def __init__(self):
        self.pam_lib = CDLL(find_library("pam"))
        self.c_lib = CDLL(find_library("c"))
        self.calloc = self.c_lib.calloc
        self.calloc.restype = c_void_p
        self.calloc.argtypes = [c_uint, c_uint]
        self.strdup = self.c_lib.strdup
        self.strdup.argtypes = [c_char_p]
        self.strdup.restype = POINTER(c_char)

        self.pam_start = self.pam_lib.pam_start
        self.pam_start.restype =  c_int
        self.pam_start.argtypes = [c_char_p, c_char_p, POINTER(Conv), POINTER(Handle)]

        self.authenticate = self.pam_lib.pam_authenticate
        self.authenticate.restype = c_int
        self.authenticate.argtypes = [Handle, c_int]

    def Auth(self, uname, password):
        @conv_func
        def my_conv(n_msg, msg, response, app_data):
            addr = self.calloc(n_msg, sizeof(Response))
            response[0] = cast(addr, POINTER(Response))
            for i in range(n_msg):
                if msg[i].contents.msg_style == 1:
                    pwd_copy = self.strdup(str(password))
                    response.contents[i].resp = cast(pwd_copy, c_char_p)
                    response.contents[i].resp_retcode = 0
            return 0
        handle = Handle()
        conv = Conv(my_conv, 0)
        rValue = self.pam_start("login", uname, pointer(conv), pointer(handle))
        return self.authenticate(handle, 0) == 0


if __name__ == "__main__":
    a = Pam()
    #Pass username and password
    #Return true if username and passowrd is correct or false
    print a.Auth("yourusername","yourpassword")
