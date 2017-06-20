# -*- coding:UTF-8 -*-
#! /usr/bin/python

import CVE_mysql

date = ''
v_type = ''

print("请输入publish日期：")
date = input()
print("请输入vulnerability_type：")
v_type = input()

date = date[:4]+'-'+date[4:6]+'-'+date[6:]

conn, cursor = CVE_mysql.connect('root', '123456', 'test', True)
cursor.execute('select * from cve_information where Publish_Date = %s and Vulnerability_Type = %s' , [date, v_type])
res = cursor.fetchall()
if len(res) == 0:
	print("数据库中不存在该条目") #数据库表中存在该条目
else:
	for r in res:
		for i in range(0,len(r)):
			if i >= 13:
				if r[i] == '':
					print("None", end='\n')
				else:
					print(r[i], end='\n')
			else:
				if r[i] == '':
					print("None", end=' ')
				else:
					print(r[i], end=' ')
