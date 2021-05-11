from flask_restful import Resource, request
from bms.models import Battery
from bms.mlpredict import MachineLearningModel
from bms import db
import csv
import os
import pandas as pd
import time


class MyApi(Resource):
    def get(self, token, task):
        battery = Battery.query.filter_by(token=token).first()
        if battery:
            if task == 'meta':
                json_battery = {'message': battery.token}
                return json_battery
            elif task == 'last':
                if os.path.exists('csv/'+token+'.csv'):
                    last_time = battery.last_time
                    if last_time:
                        return {'message': last_time}
                    return {'message': '0'}
                with open('csv/' + token + '.csv', 'a+', newline='') as f:
                    dataset = csv.writer(f, delimiter=',')
                    dataset.writerow(['cycles', 'time', 'current', 'voltage', 'temp', 'index', 'soc', 'soh'])
                return {'message': '0'}
            return {'message': 'no-task'}
        return {'message': 'invalid-token'}

    def put(self, token, task):
        battery = Battery.query.filter_by(token=token).first()
        if battery:
            if task == 'write':
                dataf = pd.read_csv('csv/' + token + '.csv')
                length = len(dataf.index)
                soc_prediction = '0'
                soh_prediction = '0'
                if length > 5:
                    predictor = MachineLearningModel(token)
                    soc_prediction = predictor.predict_soc()
                    soh_prediction = predictor.predict_soh()
                with open('csv/'+token+'.csv', 'a', newline='') as f:
                    dataset = csv.writer(f, delimiter=',')
                    dataset.writerow([request.form['cycles'],
                                      request.form['time'],
                                      request.form['current'],
                                      request.form['voltage'],
                                      request.form['temp'],
                                      request.form['index'],
                                      soc_prediction,
                                      soh_prediction
                                      ])
                battery.last_soc = soc_prediction
                battery.last_health = soh_prediction
                battery.last_temp = '%.2f' % float(request.form['temp'])
                battery.last_voltage = '%.2f' % float(request.form['voltage'])
                battery.last_time = request.form['index']
                db.session.commit()
                return {'message': 'ok'}
            return {'message': 'no-task'}
        return {'message': 'invalid-token'}


