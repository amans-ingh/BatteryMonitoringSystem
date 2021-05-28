from iot import InternetOfThings
import multiprocessing


dev1 = InternetOfThings(end='https://bms.cargo.win/api/').start()
p1 = multiprocessing.Process(target=dev1)

if __name__ == '__main__':
    p1.start()
