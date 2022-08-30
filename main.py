import requests
import json
import time
import uuid
import urllib
from pyDes import des, CBC, PAD_PKCS5
import base64
import hashlib
import re
from Crypto.Cipher import AES

class OPS:
    apis =  [
        'wec-counselor-sign-apps/stu/sign/getStuSignInfosInOneDay',
        'wec-counselor-sign-apps/stu/sign/detailSignInstance',
        'wec-counselor-sign-apps/stu/sign/submitSign',
        'wec-counselor-sign-apps/stu/oss/getUploadPolicy',
        'wec-counselor-sign-apps/stu/sign/previewAttachment'
    ]
    host = 'https://aust.campusphere.net/'
    taskInfo = None
    task = None
    user_forms = [
      {'form': {'title': '今天你的体温是多少？', 'value': '37.2℃及以下'}},
      {'form': {'title': '今天你的身体状况是？', 'value': '健康'}},
      {'form': {'title': '你现在所在地？', 'value': '是'}}
    ]
    submit_form = {}
    lonlat = {'lon': 117.033105, 'lat': 32.556596}
    nio_loc = None
    address = "中国安徽省淮南市田家庵区泰丰大街168号"
    address = ""
  
  
    def __init__(self, username, password):
      self.username = username
      self.session, cookies = self.login(username, password)
      self.session.cookies = cookies
    def login(self, username, password):
        s = requests.session()
        headers = {
            'User-Agent':
            'Mozilla/5.0 (Linux; Android 8.0.0; MI 6 Build/OPR1.170623.027; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.131 Mobile Safari/537.36 okhttp/3.12.4',
        }
        s.headers = headers
        ltInfo = s.post('https://aust.campusphere.net/iap/security/lt',data=json.dumps({})).json()
        params = {}
        params['lt'] = ltInfo['result']['_lt']
        params['rememberMe'] = 'false'
        params['dllt'] = ''
        params['mobile'] = ''
        params['username'] = username
        params['password'] = password
        data = s.post('https://aust.campusphere.net/iap/doLogin',params=params,verify=False,allow_redirects=False)
        if data.status_code == 302:
          data = s.post(data.headers['Location'], verify=False)
          return s, s.cookies
        else:
          raise Exception('用户名密码不匹配，请检查')
      
    def getUnSignTask(self):
          headers = self.session.headers
          headers['Content-Type'] = 'application/json'
          # 第一次请求接口获取cookies（MOD_AUTH_CAS）
          url = self.host + self.apis[0]
          self.session.post(url,
                            headers=headers,
                            data=json.dumps({}),
                            verify=False)
          # 第二次请求接口，真正的拿到具体任务
          res = self.session.post(url,
                                  headers=headers,
                                  data=json.dumps({}),
                                  verify=False).json()
          if len(res['datas']['unSignedTasks']) < 1:
              if len(res['datas']['leaveTasks']) < 1:
                  raise Exception('当前暂时没有未签到的任务哦！')
              latestTask = res['datas']['leaveTasks'][0]
          else:
              latestTask = res['datas']['unSignedTasks'][0]
          self.taskInfo = {
              'signInstanceWid': latestTask['signInstanceWid'],
              'signWid': latestTask['signWid']
          }
          # print(url)
          # print(res)

    # 获取具体的签到任务详情
    def getDetailTask(self):
        url = self.host + self.apis[1]
        headers = self.session.headers
        headers['Content-Type'] = 'application/json'
        res = self.session.post(url,
                                headers=headers,
                                data=json.dumps(self.taskInfo),
                                verify=False).json()
        self.task = res['datas']
        # print(res)
        # print(self.task)

    def fillForm(self):
        # 判断签到是否需要照片
        self.submit_form['signPhotoUrl'] = ''
        if 'isNeedExtra' in self.task:
            self.submit_form['isNeedExtra'] = self.task['isNeedExtra']
        else:
            self.task['isNeedExtra'] = 0
        if self.task['isNeedExtra'] == 1:
            extraFields = self.task['extraField']
            userItems = self.user_forms
            extraFieldItemValues = []
            for i in range(len(extraFields)):
                userItem = userItems[i]['form']
                extraField = extraFields[i]
                extraFieldItems = extraField['extraFieldItems']
                flag = False
                data = 'NULL'
                for extraFieldItem in extraFieldItems:
                    if extraFieldItem['isSelected']:
                        data = extraFieldItem['content']
                    # print(extraFieldItem)
                    if extraFieldItem['content'] == userItem['value']:
                        if extraFieldItem['isOtherItems'] == 1:
                            if 'extra' in userItem:
                                flag = True
                                extraFieldItemValue = {
                                    'extraFieldItemValue': userItem['extra'],
                                    'extraFieldItemWid': extraFieldItem['wid']
                                }
                                extraFieldItemValues.append(
                                    extraFieldItemValue)
                            else:
                                raise Exception(
                                    f'\r\n第{ i + 1 }个配置出错了\r\n表单未找到你设置的值：[{userItem["value"]}],\r\n该选项需要extra字段'
                                )
                        else:
                            flag = True
                            extraFieldItemValue = {
                                'extraFieldItemValue': userItem['value'],
                                'extraFieldItemWid': extraFieldItem['wid']
                            }
                            extraFieldItemValues.append(extraFieldItemValue)
                if not flag:
                    raise Exception(
                        f'\r\n第{ i + 1 }个配置出错了\r\n表单未找到你设置的值：[{userItem["value"]}],\r\n你上次系统选的值为：[{data}]'
                    )
            self.submit_form['extraFieldItems'] = extraFieldItemValues
        self.submit_form['signInstanceWid'] = self.task['signInstanceWid']
        self.submit_form['longitude'] = self.lonlat['lon']
        self.submit_form['latitude'] = self.lonlat['lat']
        self.submit_form['isMalposition'] = self.task['isMalposition']
        self.submit_form['abnormalReason'] = ''
        self.submit_form['position'] = self.address
        self.submit_form['uaIsCpadaily'] = True
        self.submit_form['signVersion'] = '1.0.0'

        print(self.submit_form)

    @staticmethod
    def DESEncrypt(s, key='b3L26XNL'):
        key = key
        iv = b"\x01\x02\x03\x04\x05\x06\x07\x08"
        k = des(key, CBC, iv, pad=None, padmode=PAD_PKCS5)
        encrypt_str = k.encrypt(s)
        return base64.b64encode(encrypt_str).decode()

    @staticmethod
    def encryptAES(data, key):
        ivStr = '\x01\x02\x03\x04\x05\x06\x07\x08\t\x01\x02\x03\x04\x05\x06\x07'
        aes = AES.new(bytes(key, encoding='utf-8'), AES.MODE_CBC,
                      bytes(ivStr, encoding="utf8"))
        text_length = len(data)
        amount_to_pad = AES.block_size - (text_length % AES.block_size)
        if amount_to_pad == 0:
            amount_to_pad = AES.block_size
        pad = chr(amount_to_pad)
        data = data + pad * amount_to_pad
        text = aes.encrypt(bytes(data, encoding='utf-8'))
        text = base64.encodebytes(text)
        text = text.decode('utf-8').strip()
        return text
  
    @staticmethod
    def md5(str):
        md5 = hashlib.md5()
        md5.update(str.encode("utf8"))
        return md5.hexdigest()

  
    def submitForm(self):
      # print(json.dumps(self.form))
      self.submitData = self.form
      self.submitApi = self.apis[2]
      extension = {
            "lon": self.lonlat['lon'],
            "model": "MI 6",
            "appVersion": "9.0.12",
            "systemVersion": "8.0.0",
            "userId": self.username,
            "systemName": "android",
            "lat": self.lonlat['lat'],
            "deviceId": str(uuid.uuid1())
        }
      headers = {
          'User-Agent':
          'Mozilla/5.0 (Linux; Android 8.0.0; MI 6 Build/OPR1.170623.027; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/92.0.4515.131 Mobile Safari/537.36 okhttp/3.12.4 cpdaily/9.0.12 wisedu/9.0.12',
          'CpdailyStandAlone': '0',
          'extension': '1',
          'Cpdaily-Extension': self.DESEncrypt(json.dumps(extension)),
          'Content-Type': 'application/json; charset=utf-8',
          'Accept-Encoding': 'gzip',
          'Host': re.findall('//(.*?)/', self.host)[0],
          'Connection': 'Keep-Alive'
      }
      print("加密表单数据中")
      formData = {
          'version':
          'first_v2',
          'calVersion':
          'firstv',
          'bodyString':
          self.encryptAES(json.dumps(self.submitData), 'ytUQ7l2ZZu8mLvJZ'),
          'sign':
          self.md5(
              urllib.parse.urlencode(self.submitData) + "&ytUQ7l2ZZu8mLvJZ")
      }
      formData.update(extension)
      print('正在尝试提交数据')
      return self.session.post(self.host + self.submitApi,
                              headers=headers,
                              data=json.dumps(formData),
                              verify=False)


if __name__ == '__main__':
  ops = OPS('2019303160','qwe147258')
  # ops.getDetailTask()
  ops.getUnSignTask()
  time.sleep(1)
  ops.getDetailTask()
  ops.fillForm()
  time.sleep(1)
  msg = ops.submit_form()
  print(msg)
  # msg = sign.submitForm()
  # print(msg)
