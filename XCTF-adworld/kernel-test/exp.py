from interactor import *

io = Interactor("61.147.171.105", 61562)
# base64 HRPKO.ko > tmp/temp.b64    # 422070
io.get_binary_file("HRPKO.ko", "./remote_HRPKO.ko")