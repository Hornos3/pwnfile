if __name__ == '__main__':
    with open("access.log", 'r') as f:
        lines = f.readlines()
        valid = []
        for l in lines:
            if 'flag' in l and 'GET' in l:
                first = l.find('"')
                second = l[first+1:].find('"')
                content = l[first + 1: first + second + 1 - 9]
                if content not in valid:
                    valid.append(content)
    with open('skeptical.txt', 'w') as f:
        f.write('\n'.join(valid))