#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import time
import copy

from checklib import *

argv = copy.deepcopy(sys.argv)

from shellouble_lib import *


class Checker(BaseChecker):
    vulns: int = 1
    timeout: int = 10
    uses_attack_data: bool = False

    def __init__(self, *args, **kwargs):
        super(Checker, self).__init__(*args, **kwargs)
        self.mch = CheckMachine(self)

    def action(self, action, *args, **kwargs):
        try:
            super(Checker, self).action(action, *args, **kwargs)
        except pwnlib.exception.PwnlibException:
            self.cquit(Status.DOWN, 'Connection error', 'Got requests connection error')

    def check(self):
        #number
        with self.mch.connection() as io:
            user1, pass1, description1 = rnd_username(), rnd_password(), rnd_string(30)

            self.mch.register(io, user1, pass1, description1,  Status.MUMBLE)
            # try login with wrong passwd
            io.sendlineafter(b'> ', b'2')
            io.sendlineafter(b': ', user1.encode())
            io.sendlineafter(b': ', rnd_password().encode())
            resp = io.recvline()[:-1]
            self.mch.c.assert_in(b'Error', resp, 'Can login with wrong password', Status.MUMBLE)
            
            # login
            self.mch.login(io, user1, pass1, Status.MUMBLE)
            self.mch.number(io, Status.MUMBLE)
            # self.mch.exit_(io)
            
            #shellcode
            self.mch.shellcode(io, Status.MUMBLE)
        self.cquit(Status.OK)
        
    def put(self, flag_id: str, flag: str):
        with self.mch.connection() as io:
            username, password = rnd_username(), rnd_password() 

            self.mch.register(io, username, password, flag, Status.MUMBLE)
            self.mch.login(io, username, password, Status.MUMBLE)
            
            self.mch.exit_(io)
            
        # self.cquit(Status.OK)
        self.cquit(Status.OK, f'{username}',f'{username}:{password}')

    def get(self, flag_id: str, flag: str):
        with self.mch.connection() as io:
            username, password = flag_id.split(':')
            self.mch.login(io, username, password, Status.CORRUPT)
            value = self.mch.show_info(io)
            self.mch.exit_(io)
            # print(flag.encode())
            self.assert_eq(value, flag.encode(), "Flag invalid", Status.CORRUPT)
            
        self.cquit(Status.OK)


if __name__ == '__main__':
    c = Checker(argv[2])

    try:
        c.action(argv[1], *argv[3:])
    except c.get_check_finished_exception():
        cquit(Status(c.status), c.public, c.private)
