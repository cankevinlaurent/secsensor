##############################################################################
- @Code:    S Project
- @Purpose: 安全扫描报告自动化工具。
- @Author:  Kévin
- @Update:  17 Oct. 2018
##############################################################################

##################
I. 项目文件
##################
- /secsensor                项目文件夹。
- secsensor.db              数据库，记录主机端口和漏洞信息。
- secsensor_enabler.py      使能程序，提供API接口，登记和查询信息。
- secsensor.py              分析报告，漏洞入库。
- start_secsensor.sh        启动脚本。
- readme_secsensor.txt      本说明文档。

##################
II. 项目部署条件
##################
- 推荐CentOS 6.9或更高
- 推荐python 2.7.14或更高
- 所在主机有vsftpd服务（端口须默认，为tcp21）且report为ftp写账号
- #visudo，增加一句：wangwei ALL=(report)   ALL
- 不需要root账号
- 正确设置文件和文件夹权限，如db文件及其全路径文件夹必须可写
- flask库：wangwei$pip install --user flask
- flask-httpauth库：wangwei$pip install --user flask-httpauth
- pyOpenSSL库：wangwei$pip install --user pyOpenSSL
- 需要beautifulsoup库


##################
III. 项目运行
##################
- 应用账号：report，部署账号：wangwei
- 启动脚本赋可执行权限：wangwei$chmod o+x start_explor.sh
- 数据库赋可写权限：wangwei$chmod o+w secsensor.db
- 数据库访问路径上各文件夹有执行权限：wangwei$chmod o+x (dirs)
- 数据库访问路径上各文件夹写权限：wangwei$chmod o+w (dirs)
- wangwei$sudo -u report ./start_secsensor.sh

##################
IV. 数据库元信息
##################
- 数据库：SQLite3
- 数据库编码：utf-8
CREATE TABLE "hosts" (
	`id`	INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
	`ip`	TEXT NOT NULL,
	`hostname`	TEXT,
	`ostype`	TEXT DEFAULT NULL,
	`portid`	TEXT DEFAULT NULL,
	`proto`	TEXT DEFAULT NULL,
	`service`	TEXT DEFAULT NULL,
	`vulname`	TEXT DEFAULT NULL,
	`timestamp`	INTEGER NOT NULL
);
CREATE TABLE sqlite_sequence(name,seq);
CREATE TABLE "vulnerbilities" (
	`vulname`	TEXT NOT NULL,
	`level`	TEXT NOT NULL,
	`desc`	TEXT NOT NULL,
	`resolution`	TEXT,
	`releasedate`	TEXT,
	`cve`	TEXT,
	PRIMARY KEY(vulname)
);
