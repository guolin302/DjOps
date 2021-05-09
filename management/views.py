from django.shortcuts import render
from django.shortcuts import redirect
from django.http import JsonResponse, HttpResponse, HttpResponseBadRequest, HttpResponseNotFound, HttpResponseRedirect
from .models import *
from django.forms.models import model_to_dict
import hashlib, json
import time, nmap, IPy
from django.contrib.auth.models import auth
from django.contrib.auth.decorators import login_required
# Create your views here.
from .Ansible2 import *

from rest_framework.viewsets import ViewSet
from rest_framework.pagination import PageNumberPagination
from management import models
from management import appseries
from rest_framework.response import Response
from rest_framework import status
import os
from django.views.decorators.clickjacking import xframe_options_exempt

from DjOps import settings

ssh_info = settings.SSH_INFO
ssh_user = ssh_info['SSH_USER']
ssh_port = ssh_info['SSH_PORT']
ssh_pass = ssh_info['SSH_PASS']


def is_super_user(func):
    '''身份认证装饰器，
    :param func:
    :return:
    '''

    def wrapper(request, *args, **kwargs):
        if not request.user.is_superuser:
            return redirect('/')
        return func(request, *args, **kwargs)

    return wrapper


def return400():
    return APIResponse(results="请求的数据不存在", status=status.HTTP_400_BAD_REQUEST, msg="失败")


class APIResponse(Response):
    def __init__(self, data, status=0, msg='成功', results=None, http_status=None,
                 headers=None, exception=False, content_type=None, **kwargs):
        # 将status、msg、results、kwargs格式化成data
        return_data = {
            'code': status,
            'msg': msg,
            'data': data,
        }
        # results只要不为空都是数据：False、0、'' 都是数据 => 条件不能写if results
        if results is not None:
            return_data['results'] = results
        # 将kwargs中额外的k-v数据添加到data中
        return_data.update(**kwargs)
        super().__init__(data=return_data, status=http_status, headers=headers, exception=exception,
                         content_type=content_type)


class HostView(ViewSet):  # ModelVi
    def list(self, request):
        hostinfo = models.Hostinfo.objects.all()
        serializer = appseries.HostinfoSerializer(hostinfo, many=True)
        return APIResponse(serializer.data)


def RunAnsible(ip, _module='ping', _args=None, _become=None, _type='model'):
    iplist = ip
    try:
        iplist.remove('')
    except Exception as e:
        print(e)
    print(iplist, _module, _args, _become,_type)
    ans = MyAnsiable(iplist=iplist, remote_user=ssh_user, become=_become, remote_password={"conn_pass": ssh_pass},
                     port=ssh_port)
    if _type == 'model':
        if _module != 'setup':
            ans.run(module=_module, args=_args)
        else:
            ans.run(module=_module)
    elif _type == 'playbook':
        ans.playbook(playbooks=_args)
    return_dic = ans.get_result()

    restr = ("success:{} failed:{} unreachable:{}".format(len(return_dic['success']), len(return_dic['failed']),
                                                          len(return_dic['unreachable'])))
    success = return_dic['success']
    unreachable = return_dic['unreachable']
    failed = return_dic['failed']
    return success, unreachable, failed, restr


@login_required
def allinfo(request):
    thepage = {}
    thepage['h1'] = '查看资源'
    thepage['name'] = '查看资源'
    allinfo = Hostinfo.objects.all()

    return render(request, 'allos.html', {'allinfo': allinfo, 'thepage': thepage})


@login_required
def index(request):
    thepage = {}
    thepage['h1'] = '主页'
    thepage['name'] = '主页'
    allmachine = Hostinfo.objects.all().count()
    phymachine = Hostinfo.objects.all().count()
    vmmachine = Hostinfo.objects.all().count()
    groupnum = AppGroup.objects.all().count()
    count = {"all": allmachine, "phy": phymachine, "vm": vmmachine, "group": groupnum}

    return render(request, 'index.html', {'thepage': thepage, 'count': count})


def login(request):
    next_url = request.GET.get('next')
    if request.method == 'POST':
        username = request.POST.get('username')
        password = request.POST.get('password')

        user = auth.authenticate(username=username, password=password)
        if user:
            auth.login(request, user)
            if next_url:
                return redirect(next_url)
            else:
                return redirect('/')
        else:
            message = '用户名或密码不正确！'
            return render(request, 'login/login.html', {'message': message})

    return render(request, 'login/login.html')


@login_required
@is_super_user
def groupinfo(request):
    thepage = {}
    thepage['h1'] = '分组信息'
    thepage['name'] = '分组概览'
    groupobj = AppGroup.objects.all()
    allinfo = {}
    for group in groupobj:
        osobj = Hostinfo.objects.filter(app=group)
        if osobj:
            allinfo[group] = osobj
        else:
            allinfo[group] = ''
    allinfo['未分组'] = Hostinfo.objects.filter(app=None)

    return render(request, 'groupinfo.html', {'allinfo': allinfo, 'thepage': thepage})


@login_required
@is_super_user
def resinfo(request):
    thepage = {}
    thepage['h1'] = '详情'
    thepage['name'] = '详细信息'
    last_html = request.META.get('HTTP_REFERER', '/')
    if request.method == 'GET':
        osid = request.GET.get('osid')
        try:
            os_info = Hostinfo.objects.get(id=osid)
            os_info = model_to_dict(os_info)
            groupinfo = AppGroup.objects.all()
            vlaninfo = Vlaninfo.objects.all()
            os_group = AppGroup.objects.get(id=os_info['app']).name
            print('666')
            return render(request, 'resinfo.html',
                          {'osinfo': os_info, 'os_group': os_group, 'thepage': thepage, 'groupinfo': groupinfo,
                           'vlaninfo': vlaninfo})
        except Exception as e:
            print(e)
            return HttpResponseRedirect(last_html)
    elif request.method == 'POST':
        try:
            print(request.POST)
            id_num = request.POST.get('id_num')
            vlan = request.POST.get('vlan')
            mem = request.POST.get('mem')
            mac = request.POST.get('mac')
            disk = request.POST.get('disk')
            vcpu = request.POST.get('vcpu')
            cpu = request.POST.get('cpu')
            sn = request.POST.get('sn')
            kernel = request.POST.get('kernel')
            notes = request.POST.get('notes')
            group = request.POST.get('group')
            osobj = Hostinfo.objects.get(id=id_num)
            osobj.app = AppGroup.objects.get(id=group)
            osobj.mac = mac
            osobj.device = disk
            osobj.vcpu = vcpu
            osobj.cpu = cpu
            osobj.mem = mem
            osobj.sn = sn
            osobj.notes = notes
            osobj.kernel = kernel
            vlanobj = Vlaninfo.objects.get(id=vlan)
            osobj.os_vlan = vlanobj
            osobj.save()

            return redirect('/resinfo/?osid={}'.format(id_num))
        except Exception as e:
            print(e, '----')
            return HttpResponseRedirect(last_html)


@login_required
@is_super_user
@xframe_options_exempt
def hostupdate(request):
    ip = request.GET.get('ip')
    if ip:
        iplist = str(ip).split(',')
        success_dic, _a, _b, restr = RunAnsible(ip=iplist, _module='setup', _become='yes')
        if success_dic:
            try:
                for ip in iplist:
                    facts_dics = success_dic[ip]['ansible_facts']
                    for network_infos in facts_dics:
                        if 'macaddress' in str(facts_dics[network_infos]) and ip in str(facts_dics[network_infos]):
                            mac = facts_dics[network_infos]['macaddress']
                            netdev = network_infos
                    kernel = facts_dics['ansible_kernel']
                    cpu = facts_dics['ansible_processor'][2]
                    vcpu = facts_dics['ansible_processor_vcpus']
                    system = facts_dics['ansible_distribution'] + facts_dics['ansible_distribution_version']
                    sn = facts_dics['ansible_product_serial']
                    memory = facts_dics['ansible_memory_mb']['real']['total']
                    hostname = facts_dics['ansible_fqdn']
                    equipment_model = facts_dics['ansible_system_vendor']
                    devices = facts_dics['ansible_devices']
                    device = {}
                    for i in devices.keys():
                        if 'storage' in facts_dics['ansible_devices'][i]['host'] or 'VMware Virtual S' in \
                                facts_dics['ansible_devices'][i]['model']:
                            device[i] = facts_dics['ansible_devices'][i]['size']
                    disk_size = 0
                    for diskname in device:
                        size = float(device[diskname].split()[0])
                        danwei = str(device[diskname].split()[1])
                        if "GB" == danwei:
                            disk_size += size
                        elif "KB" == danwei:
                            disk_size += size / 1024
                    disk_size = int(disk_size)
                    ip_obj = Hostinfo.objects.get(ip=ip)
                    ip_obj.mac = mac
                    ip_obj.hostname = hostname
                    ip_obj.cpu = cpu
                    ip_obj.vcpu = vcpu
                    ip_obj.disk = disk_size
                    ip_obj.system = system
                    ip_obj.kernel = kernel
                    ip_obj.sn = sn
                    ip_obj.mem = memory
                    ip_obj.equipment_model = equipment_model
                    ip_obj.save()

                return HttpResponse(restr)
            except Exception as e:
                return HttpResponse(str(e))
    last_html = request.META.get('HTTP_REFERER', '/')
    return HttpResponseRedirect(last_html)


@login_required
@is_super_user
def groupupdate(request):
    name = request.GET.get('name')
    if name:
        groupobj = AppGroup.objects.get(name=name)
        osobj = Hostinfo.objects.filter(app=groupobj)
        for ip in osobj:
            RunAnsible(ip.ip)
    last_html = request.META.get('HTTP_REFERER', '/')
    return HttpResponseRedirect(last_html)


@login_required
@is_super_user
def scan(request):
    thepage = {}
    thepage['h1'] = '扫描'
    thepage['name'] = '网段扫描'
    if request.method == 'POST':
        vlan = request.POST.get('lan')
        group = request.POST.get('comment')
        vlanobj = Vlaninfo.objects.get(vlan_net=vlan)
        if vlanobj:

            nm = nmap.PortScanner()
            nm.scan(vlan, ssh_port, '-sS')
            hosts_list = [(x, nm[x]['tcp'][22]['state']) for x in nm.all_hosts()]
            iplist = []
            for ip, status in hosts_list:
                groupobj = AppGroup.objects.get(group_name=group)
                if status == 'open':
                    if not Hostinfo.objects.filter(os_ip=ip):
                        addos = Hostinfo.objects.create(os_ip=ip, os_vlan=vlanobj)
                        addos.os_group.add(groupobj)
                        print("create", ip, groupobj)
                    else:
                        addos = Hostinfo.objects.get(os_ip=ip, os_vlan=vlanobj)
                        addos.os_group.add(groupobj)
                        print("add", ip, groupobj)

            last_html = request.META.get('HTTP_REFERER', '/')
            return HttpResponseRedirect(last_html)
    vlaninfo = Vlaninfo.objects.all()
    groupinfo = AppGroup.objects.all()
    return render(request, 'scan.html', {'vlaninfo': vlaninfo, 'groupinfo': groupinfo, 'thepage': thepage})


def get_sh_file(fdir, fstr):
    fileList = []
    path = str(settings.BASE_DIR) + "/DjOps/localfile" + fdir
    # 先添加目录级别

    for cur_dir, dirs, files in os.walk(path):
        for f in files:  # 当前目录下的所有文件

            if f.endswith(fstr):
                file_path = "{}/{}".format(cur_dir, f)
                fileList.append({'name': f, 'path': file_path})
    return fileList


@login_required
@is_super_user
@xframe_options_exempt
def shell(request):
    fileList = []
    shell_res = []
    if request.method == 'POST':
        iplist = request.POST.getlist('ip')
        ctype = request.POST.get('type')
        is_sudo = request.POST.get('open')
        if ctype == 'script':
            fileList = get_sh_file("/shell", '.sh')
        elif ctype == 'playbook':
            fileList = get_sh_file("/playbook", '.yml')
        if ctype == 'script':
            command = request.POST.get('script')
            script_args = request.POST.get('script_args')
            command = "{} {}".format(command, script_args)
        elif ctype == 'shell':
            command = request.POST.get('shell')
        else:
            command = False
        if is_sudo == 'on':
            become = 'yes'
        else:
            become = None
        if iplist:
            if ctype == 'playbook':
                command = request.POST.get('playbook')
                print(command)
                success, unreachable, failed, restr = RunAnsible(ip=iplist,_args=command, _type='playbook',_become=become)
            else:
                success, unreachable, failed, restr = RunAnsible(ip=iplist, _module=ctype, _args=command,
                                                                 _become=become)
            for i in iplist:
                resdic = {}
                resstr = ''
                resdic['resstr'] = ""
                cmdstr = "{} $: {}\n".format(i, command)
                resdic['cmdstr'] = cmdstr
                if success.get(i):
                    resstr += str(success.get(i)['stdout']) + "\n"
                    resdic['resstr'] += resstr
                if unreachable.get(i):
                    resstr += str(unreachable.get(i)['msg']) + "\n"
                    resdic['resstr'] += resstr
                if failed.get(i):
                    resstr += str(failed.get(i)['msg']) + "\n"
                    resdic['resstr'] += resstr
                shell_res.append(resdic)


        else:
            last_html = request.META.get('HTTP_REFERER', '/')
            return HttpResponseRedirect(last_html)
    else:

        iplist = str(request.GET.get('ip')).split(',')[:-1]
        ctype = request.GET.get('type')
        if ctype == 'script':
            fileList = get_sh_file("/shell", '.sh')
        elif ctype == 'playbook':
            fileList = get_sh_file("/playbook", '.yml')
        print(fileList, 1111111111)
        if len(iplist) == 0:
            print(iplist, len(iplist))
            last_html = request.META.get('HTTP_REFERER', '/')
            return HttpResponseRedirect(last_html)
    return render(request, 'shell.html',
                  {'filelist': fileList, 'iplist': iplist, 'shell_res': shell_res, 'run_type': ctype})


def logout(request):
    auth.logout(request)
    return redirect('/login/')
