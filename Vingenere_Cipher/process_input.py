import re
plaintext = ''
with open('input','r') as f:
    for line in f:
        plaintext += re.sub('[^A-Za-z]','',line)
    print(plaintext.lower())
