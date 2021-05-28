import requests
import csv


class InternetOfThings:
    def __init__(self, end=None, token=None):
        if end:
            self.end = end
        else:
            self.end = input("Enter the endpoint: ")
        if token:
            self.token = token
        else:
            self.token = input("Enter the token: ")

    def auth(self):
        print('authenticating...')
        response = requests.get(self.end + self.token + '/meta')
        if response:
            response_json = response.json()
            if response_json['message'] == self.token:
                print('authenticated successfully')
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
        response = requests.put(self.end + self.token + '/write', data=row_data)
        if response:
            response_json = response.json()
            if response_json['message'] == 'ok':
                comment = response_json['comment']
                if comment:
                    print('Comment: ' + comment)
                return 'success'
            else:
                return 'auth-error'
        return 'auth-error'

    def start(self):
        authentication = self.auth()
        if authentication == 'success':
            print("Uploading data")
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
                        if w == 'auth-error':
                            print("Battery deleted from the server")
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
                            if w == 'auth-error':
                                print("Battery Deleted from the server")
                                break
        else:
            print('Authentication error')
