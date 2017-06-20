# 问题2
-------
A.定时譬如每小时爬取 https://www.cvedetails.com/vulnerability-list.php 的CVE数据,存入mysql  
B.搭建一个Server提供根据publish日期，vulnerability_type获取对应CVE信息  
C.结果示例  
 ./Server  

 ./Client  20151023    Dos  
 示例输出:  
 10703     CVE-2015-6987        20              DoS  2015-10-23       2015-10-26       2.1   None         Local         Low  Not required    None         None         Partial  
 The File Bookmark component in Apple OS X before 10.11.1 allows local users to cause a denial of service (application crash) via crafted bookmark metadata in a folder.  

## 解法：
 主要文件为：main.py， CVE_url.py，CVE_mysql.py。其中CVE_mysql.py模块中主要是对数据库的操作，例如创建数据库表，判断数据是否在数据库中存在，插入数据库，统计数据库中条目数量等等；CVE_url.py主要是用于爬取页面整个信息，同时包括了一些正则操作，例如获取关键字信息，获取页面中的条目数量，以及获取整个网站中的所有链接；main.py为主函数模块，包括了整个爬取的逻辑应用，时间调度。

 在main.py模块中，main()为主函数，通过递归调度实现1小时爬取一次网站的功能。并在main函数中在需要更新数据信息的时候开始爬取页面，并开启了两个进程，第一个进程中用于爬取页面信息，提取关键字，在爬取页面信息的过程中开辟了10个线程分别用于爬取页面。第二个进程是将提取的关键字存入数据库中，这里首先需要验证数据库中是否已经存储了该信息，若没有则将该信息存入数据库中。