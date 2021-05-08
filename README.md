# DjOps
# Python 3.9.2
```
sudo mkdir /etc/ansible/
sudo ln -s ./ansible.cfg /etc/ansible/
yum install nmap sshpass -y
pip install  -r requirements.txt
python manage.py  makemigrations
python manage.py migrate
python manage.py createsuperuser
python manage.py runserver
```
# 页面操作
* admin 后台服务器列表添加机柜，设备类型，应用，网段地址，新建的第一个可以写成默认xx（默认机柜、默认机房。。。。）
* admin 后台添加主机，填写IP 保存
* 前端----资源管理----查看资源----更新
