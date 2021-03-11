import requests
import os
import json
import csv
import time


class InternetOfThings:
    def __init__(self, end=None, token=None):
        self.end = end
        self.token = token

    def auth(self):
        print('authenticating...')
        response = requests.get(self.end + self.token + '/meta')
        if response:
            response_json = response.json()
            if response_json['message'] == self.token:
                return 'success'
            return 'failed'
        return 'failed'

    def last(self):
        response = requests.get(self.end + self.token + '/last')
        if response:
            response_json = response.json()
            if response_json['message'] == '0':
                return 'success'
            return response_json['message']
        return 'failed'

    def write(self, row_data):
        print('data = ' + str(row_data))
        response = requests.put(self.end + self.token + '/write', data=row_data)
        print(response.json())
        if response:
            response_json = response.json()
            print(response_json['message'])
            if response_json['message'] == 'ok':
                return 'success'
            elif response_json['message'] == 'invalid-token':
                print("Authentication error")
                return 'auth-error'
            return 'failed'
        return 'failed'

    def meta(self):
        if self.end:
            if self.token:
                if self.auth() == 'success':
                    return 'success'
                else:
                    self.token = None
                    self.end = None
                    return 'failed'
            else:
                self.token = input("Please enter the token provided: ")
                if self.auth() == 'success':
                    with open(self.token + '.json', 'w') as token_json_file:
                        json.dump({'endpoint': self.end, 'token': self.token}, token_json_file)
                    return 'success'
                else:
                    self.token = None
                    self.end = None
                    return 'failed'

        elif self.token:
            if self.end:
                if self.auth() == 'success':
                    return 'success'
                else:
                    self.token = None
                    self.end = None
                    return 'failed'
            else:
                if os.path.exists(self.token + '.json'):
                    data = json.load(open(self.token + '.json', 'r'))
                    self.end = data['endpoint']
                    if self.auth() == 'success':
                        return 'success'
                    else:
                        self.token = None
                        self.end = None
                        return 'failed'
                else:
                    self.end = input("Please input the API endpoint: ")
                    if self.auth() == 'success':
                        with open(self.token + '.json', 'w') as token_json_file:
                            json.dump({'endpoint': self.end, 'token': self.token}, token_json_file)
                        return 'success'
                    else:
                        self.token = None
                        self.end = None
                        return 'failed'
        else:
            self.token = input("Please enter the token provided: ")
            if os.path.exists(self.token + '.json'):
                data = json.load(open(self.token + '.json', 'r'))
                self.end = data['endpoint']
                if self.auth() == 'success':
                    return 'success'
                else:
                    self.token = None
                    self.end = None
                    return 'failed'
            else:
                self.end = input("Enter the API endpoint: ")
                if self.auth() == 'success':
                    with open(self.token + '.json', 'w') as token_json_file:
                        json.dump({'endpoint': self.end, 'token': self.token}, token_json_file)
                    return 'success'
                else:
                    self.token = None
                    self.end = None
                    return 'failed'

    def start(self):
        authentication = self.meta()
        if authentication == 'success':
            last_time = self.last()
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
                        w = self.write(row_json)
                        while w != 'success':
                            if w == 'failed':
                                print('failed')
                                time.sleep(2)
                                w = self.write(row_json)
                            else:
                                break
                        if w == 'auth-error':
                            break

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
                            w = self.write(row_json)
                            while w != 'success':
                                if w == 'failed':
                                    time.sleep(2)
                                    w = self.write(row_json)
                                else:
                                    break
                            if w == 'auth-error':
                                break
        else:
            os.remove(self.token + '.json')
