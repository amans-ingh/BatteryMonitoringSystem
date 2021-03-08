import requests

BASE = 'http://localhost:80/'
response = requests.put(BASE + 'api/e21a87c7e37d0df0d0f31db2ccea869072e93982157f00eb42e832274a0f').json()
print(response['message'])