import datetime

with open('/app/crontest.txt', 'w') as f:
    f.write(str(datetime.datetime.utcnow()))

# from penquins import Kowalski
#
# # load secrets:
# with open('secrets.json') as sjson:
#     secrets = json.load(sjson)