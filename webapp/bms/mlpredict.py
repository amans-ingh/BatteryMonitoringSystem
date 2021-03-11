import joblib
import pandas as pd
import numpy as np


def correction(y):
    for i in range(len(y)):
        if y[i] > 100:
            y[i] = 100
        if y[i] < 0:
            y[i] = 0
    return y


class MachineLearningModel:
    def __init__(self, token):
        self.token = token

    def predict_soc(self):
        model = joblib.load('bms/ml-models/soc-model.sav')
        x = pd.read_csv('csv/' + self.token + '.csv')
        soc = '%.2f' % model.predict(np.array(x.iloc[-1][:5]).reshape(1, -1))
        return soc
