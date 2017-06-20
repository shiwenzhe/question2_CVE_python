# -*- coding:UTF-8 -*-
#! /usr/bin/python

import urllib.request
import re
import socket
import time

timeout = 20    
socket.setdefaulttimeout(timeout)#这里对整个socket层设置超时时间。后续文件中如果再使用到socket，不必再设置
sleep_download_time = 10

#----------------对网页的操作------------------
# 获取页面信息
def get_url(url):
	try:
		#设置延时
		time.sleep(sleep_download_time)

		request		= urllib.request.Request(url)
		response	= urllib.request.urlopen(request)
		page		= response.read()
		response.close()
		data		= page.decode('utf-8')
	except UnicodeDecodeError as e:
	    print('-----UnicodeDecodeError url:',url)  
    
	except urllib.error.URLError as e:  
	    print("-----urlError url:",url)  
	  
	except socket.timeout as e:  
	    print("-----socket timout:",url)  
	return data

# 获取关键数据
def get_keyvalues(data):
	keyvalues = re.findall(r'<tr class="srrowns">\s+<td class="num">.*?\s+(\d+)\s+</td>\s+<td nowrap.*?><.*?>(CVE-\d{4}-\d+)</a></td>\s+<td>(<a.*?>)?(.*?)(</a>)?</td>\s+<td class="num">\s+<b.*?>\s+(\d*)\s+</b>\s+</td>\s+<td>\s*(.*?)\s*</td>\s+<td>(.*?)</td>\s+<td>(.*?)</td>\s+<td><div.*?>(.*?)</div></td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+<td.*?>(.*?)</td>\s+</tr>\s+<tr>\s+<td.*?>\s+(.*?)\s+</td>\s+</tr>', data, re.S)
	return keyvalues
#[item[1], item[3], item[5], item[6], item[7], item[8], item[9], item[10], item[11], item[12], item[13], item[14], item[15], item[16], item[17] ]

# 获取整个网站的数据数量
def get_counts(data):
	CVE_count = re.findall(r'<div class="paging" id="pagingb">[\s\S]*?Total number of vulnerabilities.*?<b>(\d+)</b>', data, re.S)
	CVE_count = int(CVE_count[0])
	return CVE_count

# 获取所有链接
def get_listurl(data):
	data_href 	= data.split('Total number of vulnerabilities :')[1];
	href 		= re.findall(r'<a[\s\S]*?href="(.*?)"[\s\S]*?title="Go to page \d*"', data_href, re.S)
	head_url 	= "https://www.cvedetails.com"
	list_url 	= []
	for h in href:
		next_url	=	head_url + h
		list_url.append(next_url)
	return list_url

# print('url import')