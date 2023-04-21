from django.shortcuts import render, redirect,HttpResponse
import json
import os
import subprocess

# 验证webhook
import hashlib
import hmac

import logging # 导入模块

logger = logging.getLogger('django') # 使用在配置文件中定义的名为“django”的日志器


# secret token git webhook
secret_key="123456" 

def verify_signature(payload_body, secret_token, signature_header):
    """Verify that the payload was sent from GitHub by validating SHA256.
    
    Raise and return 403 if not authorized.
    
    Args:
        payload_body: original request body to verify (request.body())
        secret_token: GitHub app webhook token (WEBHOOK_SECRET)
        signature_header: header received from GitHub (x-hub-signature-256)
    """
    if not signature_header:
        raise HttpResponse('x-hub-signature-256 header is missing!', status=403)
    hash_object = hmac.new(secret_token.encode('utf-8'), msg=payload_body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()
    if not hmac.compare_digest(expected_signature, signature_header):
        raise HttpResponse("Request signatures didn't match!", status=403)
    return 1


#以下两行的作用是让结果唯一：
from langdetect import DetectorFactory
DetectorFactory.seed = 0


def autopull(request):
    # if request.method=='GET':
    #     logger.info(os.getcwd())
    #     olddir=os.getcwd()
    #     logger.info("------------ old dir: "+os.getcwd()+"--------------") # 调用logger.info()方法输出Info级别的日志
    #     command="cd ../Netpp"
    #     x=os.system(command)
    #     logger.info("----------------os.system("+command+")执行状态码(0 means success)：")
    #     logger.info(x)
    #     logger.info(os.getcwd())
    #     newdir=os.getcwd()
    #     logger.info("------------ after cmd dir: "+os.getcwd()+"--------------")

    #     # subprocess.Popen(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    #     # os.chdir('/Netpp')
    #     chd=os.getcwd()
    #     ans={"old dir":olddir,"new dir":newdir,"chdir":chd,"comand status":x}
    #     return HttpResponse(json.dumps(ans)) 
        
    if request.method=='POST':
        sig_header=request.headers.get('X-Hub-Signature-256')
        if verify_signature(request.body,secret_key,sig_header):

            os.chdir("/Netpp")
            
            logger.info("------------     "+os.getcwd()+"    --------------") # 调用logger.info()方法输出Info级别的日志
            command="git pull origin main"

            # x=os.system(command)
            x=os.popen(command)
            # logger.info("----------------os.system("+command+")执行状态码：")
            # logger.info(x)
            ans={"status":x.read()}
            return HttpResponse(json.dumps(ans))
        else:
            logger.info("------------no match--------------") # 调用logger.info()方法输出Info级别的日志
            ans={"status":"pull fail"}
            return HttpResponse(json.dumps(ans))    
    

