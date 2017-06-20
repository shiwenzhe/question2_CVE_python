# -*- coding:UTF-8 -*-
#! /usr/bin/python
from multiprocessing import Process, Queue
import os

import urllib.request
import re
import mysql.connector  # 导入MySQL驱动:

import threading

import time
import socket

import sched

timeout = 20    
socket.setdefaulttimeout(timeout)#这里对整个socket层设置超时时间。后续文件中如果再使用到socket，不必再设置 
sleep_download_time = 10  

s = sched.scheduler(time.time, time.sleep)

class ThreadSpider(threading.Thread):
	def __init__(self, index, q_url, q_html_data, block_queue_spider): #线程构造函数
		threading.Thread.__init__(self)
		self.index = index
		self.q_url = q_url
		self.q_html_data = q_html_data
		self.block_queue_spider = block_queue_spider
	def run(self):
		while 1:
			#print('threading %d working' % (self.index))
			time.sleep(sleep_download_time) #这里时间自己设定
			my_url = self.q_url.get(True)

			if not self.block_queue_spider.empty():
				val = self.block_queue_spider.get()
				if val == 'finish':
					#print('new data have been inserted finished....')
					break

			if my_url == 'none':#循环终止条件
				#print('q_url is empty~~~~~~')
				break
			else:
				webPage = urllib.request.urlopen(my_url)
				data = webPage.read()
				webPage.close()
				data = data.decode('utf-8')
				self.q_html_data.put(data)
			
		#print('000000000000000000000000')

# 子进程1要执行的代码-抓取网页 1h更新一次
def run_spider(q_html_data, last_spider_page_n, block_queue_opre, block_queue_spider):
	url = "https://www.cvedetails.com/vulnerability-list.php"
	webPage = urllib.request.urlopen(url)
	data = webPage.read()
	webPage.close()
	data = data.decode('utf-8')

	data_href = data.split('Total number of vulnerabilities :')[1];

	# 获取其他所有页面地址，放入q_url
	href = re.findall(r'<a[\s\S]*?href="(.*?)"[\s\S]*?title="Go to page \d*"', data_href, re.S)

	# 统计网站中所有数据的条数,确定需要更新的数据的数量
	CVE_count = re.findall(r'<div class="paging" id="pagingb">[\s\S]*?Total number of vulnerabilities.*?<b>(\d+)</b>', data, re.S)
	CVE_count = int(CVE_count[0])

	# 其他页面url首部
	h_url = "https://www.cvedetails.com"
	q_url = Queue()
	for h in href:
		nexturl = h_url+h
		q_url.put(nexturl)
	for i in range(10):
		q_url.put('none')
		
	# last_spider_page_n 数据库中现有的数据条目数量
	#需要计算抓取的数据条数
	CVE_new = CVE_count - last_spider_page_n
	#last_spider_page_n = CVE_count

	block_queue_opre.put(CVE_new)
	#print('there are %d data need to be inserted' % (CVE_new))

	if CVE_new == 0:
		return
	# 开辟10条线程进行网页爬取工作
	for index in range(10):
		thread = ThreadSpider(index, q_url, q_html_data, block_queue_spider)
		thread.start()
	##print("spider finished---------")
		
# 子进程2要执行的代码-解析网页
def run_opre(q_html_data, q_key_values, block_queue_opre, block_queue_save, block_queue_spider):
	CVE_new = block_queue_opre.get(True)
	block_queue_save.put(CVE_new)

	while 1:
		#print('getting html in opre')
		data = q_html_data.get(True)
		#print('============>')

		keyvalues = re.findall(r'<tr class="srrowns">\s+<td class="num">.*?\s+(\d+)\s+</td>\s+<td nowrap.*?><.*?>(CVE-\d{4}-\d+)</a></td>\s+<td>(<a.*?>)?(.*?)(</a>)?</td>\s+<td class="num">\s+<b.*?>\s+(\d*)\s+</b>\s+</td>\s+<td>\s*(.*?)\s*</td>\s+<td>(.*?)</td>\s+<td>(.*?)</td>\s+<td><div.*?>(.*?)</div></td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+</tr>\s+<tr>\s+<td.*?>\s+(.*?)\s+</td>\s+</tr>', data, re.S)
				
		q_key_values.put(keyvalues)

		# 更新数据结束，则停止解析网页
		if not block_queue_save.empty():
			val = block_queue_save.get()
			if val == 'finish':
				#print('opre finised <<<<<<<<<<<<<<<')
				for i in range(10):
					block_queue_spider.put('finish')
				break
			else:
				#print('put back to block_queue_save...')
				block_queue_save.put(val)

	#print('2222222222222222222222')

# 子程序要执行的代码-存储关键字
def run_save(q_key_values, block_queue_save):
	conn = mysql.connector.connect(user='root', password='123456', database='test', use_unicode=True)
	cursor = conn.cursor()
	
	CVE_new = block_queue_save.get(True)
	data_updated = CVE_new
	while 1:
		if CVE_new == 0:
			#关闭数据库连接
			cursor.close()
			conn.close()
			block_queue_save.put('finish')			
			#print('save finised <<<<<<<<<<<<<<<')
			print('there are',data_updated,'data has been updated')
			break

		#print('getting key values in save')
		key_value = q_key_values.get(True)
		#print('------------->')
		for item in key_value:
			# 在数据库中查找该条数据是否已经存在
			cursor.execute('select * from user where CVE_ID = %s' , [item[1]])
			res = cursor.fetchall()
			if len(res) != 0:
				continue
			else:
				CVE_new -= 1;

			# 插入一行记录，注意MySQL的占位符是%s:
			cursor.execute('insert into user (CVE_ID, CWE_ID, Exploits, Vulnerability_Type, Publish_Date, Update_Date, Score, Gained_Access_Level, Access, Complexity, Authentication, Conf, Integ, Avail, Details) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', [item[1], item[3], item[5], item[6], item[7], item[8], item[9], item[10], item[11], item[12], item[13], item[14], item[15], item[16], item[17] ])
		
		##print('%d finished save ...' % (val))
		#提交事务:
		conn.commit()
		#print('----process save----there are %d data lefted' % (CVE_new))
	#print('1111111111111111')

def run_function():

	#进程间消息队列，q_html_data存放整个网页的数据
	q_html_data = Queue()
	#q_html_data.put(data)
	#进程间消息队列，q_key_values存放提取出的关键字
	q_key_values = Queue()

	block_queue_opre = Queue()
	block_queue_save = Queue()
	block_queue_spider = Queue()

	#获取数据库中已经有了多少条数据
	conn = mysql.connector.connect(user='root', password='123456', database='test', use_unicode=True)
	cursor = conn.cursor()

	# 创建user表（判断是否存在user表）
	cursor.execute('show tables')
	table_name = cursor.fetchall()
	has_table = 0
	for t_n in table_name:
		if t_n[0] == 'user':
			has_table = 1
			break
	if has_table != 1:
		cursor.execute('create table user (CVE_ID varchar(20) primary key, CWE_ID varchar(20), Exploits varchar(20), Vulnerability_Type varchar(50), Publish_Date date, Update_Date date, Score varchar(20), Gained_Access_Level varchar(20), Access varchar(20), Complexity varchar(20), Authentication varchar(20), Conf varchar(20), Integ varchar(20), Avail varchar(20), Details text)')

	#获取数据库中已经有了多少条数据
	cursor.execute('select count(*) from user')
	last_spider_page_n = cursor.fetchall()
	last_spider_page_n = last_spider_page_n[0][0]
	cursor.close()
	conn.close()

	#进程1：爬去网页信息
	p_spider = Process(target=run_spider, args=(q_html_data, last_spider_page_n, block_queue_opre, block_queue_spider, ))
	#进程2：解析网页信息
	p_opre = Process(target=run_opre, args=(q_html_data, q_key_values, block_queue_opre, block_queue_save, block_queue_spider, ))
	#进程2：向数据库中存储关键字
	p_save = Process(target=run_save, args=(q_key_values, block_queue_save, ))

	print('start......')
	p_spider.start()
	p_opre.start()
	p_save.start()

	p_spider.join()
	#print('3333333333333333')

	p_save.join()
	#print('555555555555555')
	p_opre.terminate()
	#print('4444444444444444')

	#一个小时调用一次本循环
	print(time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()))
	s.enter(3600, 1, run_function, ())
	s.run()

if __name__ == '__main__':

	run_function()
	
	

