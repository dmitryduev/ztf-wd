import datetime

with open('/app/crontest.txt', 'w') as f:
    f.write(str(datetime.datetime.utcnow()))

