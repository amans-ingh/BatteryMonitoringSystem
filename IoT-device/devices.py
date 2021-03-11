from iot import InternetOfThings
# import multiprocessing


dev1 = InternetOfThings(end='https://home.cargo.win/api/', token='b1a7b08ba7e6e1a161ffe13317c41c267bb1c470df2e2ca8f0a35a4d3709')
dev1.start()
# dev2 = InternetOfThings(end='https://home.cargo.win/api/', token='8147fdb06e6bbbc3b505b42fab55eee3e83d8eae87e2c7e8c04193bee3f8')


# p1 = multiprocessing.Process(target=dev1.start)
# p2 = multiprocessing.Process(target=dev2.start)
#
# if __name__ == '__main__':
#     p1.start()
#     # p2.start()

#     # p1.join()
#     # p2.join()
