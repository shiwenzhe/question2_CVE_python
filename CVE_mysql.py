# -*- coding:UTF-8 -*-
#! /usr/bin/python


import mysql.connector #导入mysql驱动

#初始化数据库表CVE_information，如果存在，直接返回，不存在则创建表CVE_information
def mysql_init(ur, pw, db, use_ud):
	conn = mysql.connector.connect(user=ur, password=pw, database=db, use_unicode=use_ud)
	cursor = conn.cursor()

	# 创建CVE_information表（判断是否存在CVE_information表）
	cursor.execute('show tables')
	table_name = cursor.fetchall()
	
	for t_n in table_name:
		if t_n[0] == 'cve_information':
			return cursor, conn

	cursor.execute('create table cve_information (CVE_ID varchar(20) primary key, CWE_ID varchar(20), Exploits varchar(20), Vulnerability_Type varchar(50), Publish_Date date, Update_Date date, Score varchar(20), Gained_Access_Level varchar(20), Access varchar(20), Complexity varchar(20), Authentication varchar(20), Conf varchar(20), Integ varchar(20), Avail varchar(20), Details text)')

	return cursor, conn

#返回数据库表中的条目数量
def mysql_len(cursor):
	cursor.execute('select count(*) from cve_information')
	length = cursor.fetchall()[0][0]
	return length

# 在数据库中查找该条数据是否已经存在
def mysql_exit(cursor, item):
	cursor.execute('select * from cve_information where CVE_ID = %s' , [item[1]])
	res = cursor.fetchall()
	if len(res) != 0:
		return True #数据库表中存在该条目
	else:
		return False

# 插入
def mysql_insert(cursor, item):
	cursor.execute('insert into cve_information (CVE_ID, CWE_ID, Exploits, Vulnerability_Type, Publish_Date, Update_Date, Score, Gained_Access_Level, Access, Complexity, Authentication, Conf, Integ, Avail, Details) values (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)', [item[1], item[3], item[5], item[6], item[7], item[8], item[9], item[10], item[11], item[12], item[13], item[14], item[15], item[16], item[17] ])

# 关闭数据库连接
def mysql_close(cursor, conn):
	cursor.close()
	conn.close()

def connect(ur, pw, db, use_ud):
	conn = mysql.connector.connect(user=ur, password=pw, database=db, use_unicode=use_ud)
	cursor = conn.cursor()
	return conn, cursor

# print('mysql import')