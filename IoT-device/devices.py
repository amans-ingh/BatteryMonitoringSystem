from iot import InternetOfThings
import multiprocessing


dev1 = InternetOfThings(end='http://127.0.0.1:5000/api/', token='afeada8d226ee0a79d5403895331c1b34047450b12c8eca5e0a97546239d')
# dev2 = InternetOfThings(end='http://localhost:5000/api/', token='8dc80caad4145862a0a74d156b54ae452c38a9868acf28bb2295744736df')
# dev3 = InternetOfThings(end='http://localhost:5000/api/', token='1497a082b52380a5019afd22bc5c0e7102cc646912a5c4260953102a93bd')
# dev4 = InternetOfThings(end='http://localhost:5000/api/', token='c1acad0a2722fc5807fa03c96e25acd9856fc28514ba5a27c728f6e21483')


p1 = multiprocessing.Process(target=dev1.start)
# p2 = multiprocessing.Process(target=dev2.start)
# p3 = multiprocessing.Process(target=dev3.start)
# p4 = multiprocessing.Process(target=dev4.start)

if __name__ == '__main__':
    p1.start()
    # p2.start()
    # p3.start()
    # p4.start()
