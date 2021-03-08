import json
import os
import requests
import csv
import time


def auth(end, api_token):
    response = requests.get(end + api_token + '/meta')
    if response:
        response_json = response.json()
        if response_json['message'] == api_token:
            return 'success'
        return 'failed'
    return 'failed'


def last(end, api_token):
    response = requests.get(end + api_token + '/last')
    if response:
        response_json = response.json()
        if response_json['message'] == '0':
            return 'success'
        return response_json['message']
    return 'failed'


def write(end, api_token, row_data):
    response = requests.put(end + api_token + '/write', data=row_data)
    if response:
        response_json = response.json()
        if response_json['message'] == 'ok':
            return 'success'
        return 'failed'
    return 'failed'


def meta():
    global token
    global endpoint
    if os.path.exists("token.json"):
        data = json.load(open('token.json', 'r'))
        token = data['token']
        endpoint = data['endpoint']
        return endpoint, token
    else:
        endpoint = input("Enter the API endpoint: ")
        token = input("Enter the API token provided: ")
        if auth(endpoint, token) == 'success':
            token_json_file = open('token.json', 'w')
            json.dump({'endpoint': endpoint, 'token': token}, token_json_file)
            return endpoint, token
        elif auth(endpoint, token) == 'failed':
            print("Invalid API token")
            meta()


[endpoint, token] = meta()
authentication = auth(endpoint, token, )
if authentication == 'success':
    last_time = last(endpoint, token)
    if last_time == 'success':
        with open('csv_iot/data.csv', 'r') as csv_data:
            csv_read = csv.reader(csv_data, delimiter=',')
            for row in csv_read:
                row_json = {'time': str(row[1]),
                            'voltage': str(row[3]),
                            'current': str(row[2]),
                            'temp': str(row[4]),
                            'cycles': str(row[0]),
                            'index': str(row[5])
                            }
                w = write(endpoint, token, row_json)
                while True:
                    if w == 'failed':
                        time.sleep(2)
                        w = write(endpoint, token, row_json)
                    elif w == 'success':
                        break
                time.sleep(1)

    elif last_time == 'failed':
        print("Incorrect information")

    else:
        with open('csv_iot/data.csv', 'r') as csv_data:
            csv_read = csv.reader(csv_data, delimiter=',')
            for row in csv_read:
                if int(row[5]) >= int(last_time) + 1:
                    row_json = {'time': str(row[1]),
                                'voltage': str(row[3]),
                                'current': str(row[2]),
                                'temp': str(row[4]),
                                'cycles': str(row[0]),
                                'index': str(row[5])
                                }
                    w = write(endpoint, token, row_json)
                    while True:
                        if w == 'failed':
                            time.sleep(2)
                            w = write(endpoint, token, row_json)
                        elif w == 'success':
                            break
                    time.sleep(1)
else:
    os.remove('token.json')
    meta()
    print("Authentication confirmed!, Please restart the program")



