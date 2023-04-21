from django.shortcuts import render, redirect,HttpResponse
import json
import os

# 验证webhook
import hashlib
import hmac

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

def bg(request):
    return render(request, 'bg.html', locals())

def about(request):
    return render(request, 'about.html', locals())

def more(request):
    return render(request, 'more.html', locals())

def vrHouse(request):
    return render(request, 'room.html',locals())

def autopull(request):
    if request.method=='POST':
        sig_header=request.headers.get('X-Hub-Signature-256')
        if verify_signature(request.body,secret_key,sig_header):
            print('\n----------------signatures match-------------------------\n')
            os.chdir("/Netpp")
            os.system("git pull --force origin main")
            ans={"status":"pull seccess"}
            return HttpResponse(json.dumps(ans))
        else:
            ans={"status":"pull fail"}
            return HttpResponse(json.dumps(ans))    
    

