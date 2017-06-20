# -*- coding:UTF-8 -*-
#! /usr/bin/python
#ques_2_CVEcrawler

import CVE_url
import CVE_mysql
import threading
import time
from multiprocessing import Process, Queue
import sched
import socket

s = sched.scheduler(time.time, time.sleep)

timeout = 20    
socket.setdefaulttimeout(timeout)#这里对整个socket层设置超时时间。后续文件中如果再使用到socket，不必再设置
sleep_download_time = 10


class ThreadSpider(threading.Thread):
	def __init__(self, num, queue_url, queue_keyvalues):
		threading.Thread.__init__(self)
		self.num = num
		self.queue_url = queue_url
		self.queue_keyvalues = queue_keyvalues

	def run(self):
		print('线程 %d 正在运行' % (self.num))
		while not self.queue_url.empty():
			url = self.queue_url.get()

			#设置延时
			time.sleep(sleep_download_time)

			data = CVE_url.get_url(url)
			keyvalues = CVE_url.get_keyvalues(data)
			self.queue_keyvalues.put(keyvalues)

		print('线程 %d 结束' % (self.num))

# 开辟10个线程进行爬虫
def threading_spider(queue_url, queue_keyvalues):
	for num in range(10):
		thread = ThreadSpider(num, queue_url, queue_keyvalues)
		thread.start()

# 开辟进程进行数据库存储
def processing_save(queue_keyvalues, update_flag):# update_flag待插入的数据数量
	conn, cursor = CVE_mysql.connect('root', '123456', 'test', True)

	while True:
		if update_flag == 0:
			CVE_mysql.mysql_close(cursor, conn)
			break

		keyvalue = queue_keyvalues.get()
		for item in keyvalue:
			if CVE_mysql.mysql_exit(cursor, item) == False:
				CVE_mysql.mysql_insert(cursor, item) #插入数据库中
				update_flag = update_flag - 1
			
		conn.commit()

	print('进程结束')


def if_update_mysql(url):
	# 连接数据库，数据库表名字为CVE_information
	cursor, conn = CVE_mysql.mysql_init('root', '123456', 'test', True)
	mysql_len = CVE_mysql.mysql_len(cursor)

	# 爬取网页
	data = CVE_url.get_url(url)
	page_len = CVE_url.get_counts(data) 

	#关闭数据库连接
	CVE_mysql.mysql_close(cursor, conn)

	# 将链接放入list中
	list_url = CVE_url.get_listurl(data)

	return page_len - mysql_len, list_url

def main(url):
	print('开始时间：', time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
	# 1 判断是否需要更新数据库
	update_flag, list_url = if_update_mysql(url)
	print("有 %d 条数据需要添加" % (update_flag))

	if update_flag != 0:
		queue_url = Queue()
		for l in list_url:
			queue_url.put(l)
		queue_keyvalues = Queue()

		# 开辟进程，提出10个线程进行爬虫
		print("开辟10个线程进行爬虫")
		process_spider = Process(target=threading_spider, args=(queue_url, queue_keyvalues, ))

		# 开辟进程进行数据库存储
		print("开辟进程进行数据库存储")
		process_save = Process(target=processing_save, args=(queue_keyvalues, update_flag, ))

		process_spider.start()
		process_save.start()

		process_spider.join()
		process_save.join()

	print('更新结束......',time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
	####等待#############
	s.enter(3600, 1, main, (url,))
	s.run()
		
if __name__ == '__main__':
	url = 'https://www.cvedetails.com/vulnerability-list.php'
	#
	print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
	main(url)

	#一个小时调用

