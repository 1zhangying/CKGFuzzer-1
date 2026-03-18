import os
import requests

# 打印当前读取到的代理配置
print("Current Proxy:", os.environ.get("https_proxy"))

try:
    # 尝试模拟一次请求
    response = requests.get("https://dashscope.aliyuncs.com", timeout=10)
    print(f"Status Code: {response.status_code}")
    print("Python 连接成功！")
except Exception as e:
    print(f"Python 连接失败: {e}")