from multiprocessing import Process


def handler(name: str, dic: dict):
    print(name)
    print(dic)
    for i in range(100):
        dic["p1"] = i
        print("p1 says:", dic["p2"])


if __name__ == '__main__':
    processes = []
    dic = {"salam": "khodafez", "chao": "chaont", 'p1': -1, 'p2': -1}
    while True:
        inp = input(">")
        if inp == "exit":
            print(dic)
            for p in processes:
                p.terminate()
            break
        else:
            dic[inp] = {'process': Process(target=handler, args=(inp, dic[inp],)), 'dic': {}}
            print("dic: ", dic)
