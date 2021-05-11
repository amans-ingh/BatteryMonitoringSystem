import joblib
import pandas as pd
import numpy as np
from bms.models import Battery


def correction(y):
    if y > 100:
        y = 100
    if y < 0:
        y = 0
    return y


class MachineLearningModel:
    def __init__(self, token):
        self.token = token

    def predict_soc(self):
        model = joblib.load('bms/ml-models/soc-model.sav')
        x = pd.read_csv('csv/' + self.token + '.csv')
        soc = model.predict(np.array(x.iloc[-1][:5]).reshape(1, -1))
        soc = correction(soc)
        soc = '%.2f' % soc
        return soc

    def predict_soh(self):
        battery = Battery.query.filter_by(token=self.token).first()
        model = joblib.load('bms/ml-models/soh-model.sav')
        x = pd.read_csv('csv/' + self.token + '.csv')
        if x.iloc[-1][0] > 2:
            mean_voltage = np.mean(x['voltage'][x['cycles'] == x.iloc[-1][0] - 1])
            mean_current = np.mean(np.abs(x['current'][x['cycles'] == x.iloc[-1][0] - 1]))
            mean_temp = np.mean(x['temp'][x['cycles'] == x.iloc[-1][0] - 1])
            y = np.array([x.iloc[-1][0], mean_voltage, mean_current, mean_temp])
            soh = model.predict(y.reshape(1, -1))
            soh = '%.2f' % soh
            if battery.last_health:
                if float(soh) < float(battery.last_health):
                    return soh
                return battery.last_health
        else:
            soh = 100
        return soh
