import pandas as pd


class MyChart:
    def __init__(self, token):
        self.token = token

    def sample(self, label, points, frame):
        dataf = pd.read_csv('csv/' + self.token + '.csv')
        total_length = len(dataf.index)
        if total_length > frame:
            dataframe = dataf.tail(frame)
            length = len(dataframe.index)
            divider = length/points
            sample = dataframe[(dataframe['index'] % divider.__round__(0) == 0)]
            return sample[label].values.tolist()
        a = self.sample_all(label=label, points=points)
        return a

    def sample_all(self, label, points):
        dataframe = pd.read_csv('csv/' + self.token + '.csv')
        length = len(dataframe.index)
        if length > points:
            divider = length / points
            sample = dataframe[(dataframe['index'] % divider.__round__(0) == 0)]
            return sample[label].values.tolist()
        return dataframe[label].values.tolist()
