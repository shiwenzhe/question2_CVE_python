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