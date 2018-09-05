#!/usr/bin/env python2

'''

@name flag_service
@author haozigege@Lancet
@version v0.1
@time 2018.9

This tool is utilized as a service to store the flag in queue, and then to send them 
at a certain speed.

Here are the routes:
admin route:   to download file
/flag?flag=xxxx&token=xxxx&ip=xxxx:         submit ur own flag
/flag_all:     print all the flag in the queue


'''

import os
import socket
import sys
import SimpleHTTPServer
import SocketServer
import requests
import cgi
import re
from time import gmtime, strftime
import threading 
import Queue
from urlparse import parse_qs,urlparse
import time


###### configuration #######

# the listen port
listen_port = 8081

# remote flag submit	
# remote_flag_url = 'https://172.17.4.1/Common/awd_sub_answer'
remote_flag_url = 'http://127.0.0.1/Common/awd_sub_answer'

# team token
token = 'a7e1ddc8600015b6a55ad1fc15cd8c2c'

# team cookie
team_cookie = {"phpsessid":"haozigege"}

# flag regex pattern
flag_regex_pattern = "[0-9a-fA-F\-]{36}"

# flag submit span
time_span = 3

# request time out
time_out = 3

# admin router for file manager
admin_router = '/haozigege666'

# file manager base
dir_base = '/tmp'

# flag submit log
flag_log_file = './flag.log'

# store the flag in the queue
flag_save_file = './flag_all'

# load flag from this file
flag_load_file = './flag_load'


############################


'''
	init the queue, if the flag_save_file is not empty
	try to load the flags into the queue, else, init a
	empty queue

'''
queue = Queue.Queue(1000)
old_flags = open(flag_load_file).readlines()
if len(old_flags) > 1:
	for old_flag in old_flags:
		if old_flag:
			queue.put(old_flag.strip())


def check_flag(flag):
	'''
		to judge whether the format of a flag is right
	'''
	r = re.search(flag_regex_pattern,flag)
	if r:
		return True
	return False


def flag_submit():
	# submit the flag
	while True:

		# get info from queue
		if queue.empty():
			continue
		info = queue.get(1).split(':')
		flag , my_token , ip , sender_ip , now_time = info

		# you may need to change the args
		data = {'token':my_token,'answer':flag}

		try:

			r = requests.post(remote_flag_url,cookies=team_cookie,data=data,timeout=time_out,verify=False)
			result = r.content
		except Exception,e:
			print e
			result = 'error: ' + str(e)
			
		check_result(result,info)

		time.sleep(time_span)


def check_result(result,info):
	if 'success' in result:
		print("success")
	elif 'error' in result:
		print("error")
	else:
		print("uncaughted error")


# my custom class to play with fun
class CustomHTTPRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):

	def do_GET(self):
		self.my_main_handle()

	def do_POST(self):
		self.my_main_handle()

	def admin_handle(self):
		'''
		play with the http data 
	
		'''

		# some error might happen when u try to enter a folder without /
		if not self.path.startswith(admin_router + '/'):
			self.send_response(301)
			self.send_header('Location', admin_router + '/')
			self.end_headers()

		# normal file list
		real_path = dir_base + self.path[len(admin_router):]
		if not real_path:
			real_path = dir_base + '/'
		if os.path.isdir(real_path):
			f = self.list_directory(real_path)
			self.copyfile(f, self.wfile)
		elif os.path.exists(real_path):
			# I am sure it's a normal file
			f = open(real_path,'rb')
			self.send_response(200)
			self.send_header('Content-type', 'text/html')
			self.end_headers()
			self.copyfile(f, self.wfile)
		return ""


	def flag_handle(self):
		'''
			receive the flag from user and push it in the queue
		'''

		params = parse_qs(urlparse(self.path).query)
		#self.log_message("%s",str(params))

		# flag to send
		if params.has_key('flag'):
			flag = params['flag'][0]
		else:
			# no flag, then error
			self.error_handle('no flag provided!')
			return

		if not check_flag(flag):
			self.error_handle('flag check error!')
			return

		# if the token has been set, use the udf token for scalability
		if params.has_key('token'):
			my_token = params['token'][0]
		else:
			# use the default token
			my_token = token

		# ip address of the victim
		if params.has_key('ip'):
			ip = params['ip'][0]
		else:
			# use the default token
			ip = 'null'

		# ip address of the sender
		sender_ip = self.client_address[0]

		# the time when receive the flag
		now_time = str(int(time.time()))

		info = flag + ':' + my_token + ':' + ip + ':' + sender_ip + ':' + now_time

		queue.put(info)
		print '[*] flag add success!'
		print '[*] info: ' + info
		print '[*] queue size ' + str(queue.qsize())
		self.success_handle('success: ' + 'qsize ' + str(queue.qsize()))


	def error_handle(self,msg):
		self.send_response(404)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		self.wfile.write(msg)

	def success_handle(self,msg):
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		self.wfile.write(msg)


	def flag_all_handle(self):
		'''
			print all the flags in the queue
		'''
		html_res = ''
		txt_res = ''

		all_flags = list(queue.queue)
		for all_flag in all_flags:
			if all_flag:
				html_res += all_flag + "<br>"
				txt_res += all_flag + "\n"


		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		self.wfile.write(html_res)

		# save the flag_all result to the flag_save_file,
		# which could be reload if restart
		open(flag_save_file,'w').write(txt_res)



	def my_main_handle(self):
		'''
		handle with the payload
		'''

		# with that admin url prefix, we can be authorized with admin priv
		if self.path.startswith(admin_router):
			self.admin_handle()
			return

		if self.path.startswith('/flag_all'):
			self.flag_all_handle()
			return 

		if self.path.startswith('/flag'):
			self.flag_handle()
			return

		self.error_handle('404 not found')




# update the server_bind function to reuse the port 
class MyTCPServer(SocketServer.TCPServer):
    def server_bind(self):
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind(self.server_address)

t = threading.Thread(target=flag_submit,name='flag_submit')
t.setDaemon(True)
t.start()



httpd = MyTCPServer(("", listen_port), CustomHTTPRequestHandler)
print "serving at port", listen_port
httpd.serve_forever()


