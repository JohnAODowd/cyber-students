PORT = 4000

MONGODB_HOST = {
    'host': 'localhost',
    'port': 27017
}

MONGODB_DBNAME = 'cyberStudents'

WORKERS = 32

'''
"A little bit of math can accomplish what all the guns and barbed wire can't: 
a little bit of math can keep a secret.” — Edward Snowden
'''

ENCRYPTION_KEY = "alittlebitofmath" # 128-bit key (16 characters in utf-8)

# Can be easily adapted to a 192-bit or 256-bit key. 
# Example:
# ENCRYPTION_KEY = "alittlebitofmathcankeepa" # 192-bit key (24 characters in utf-8)
# ENCRYPTION_KEY = "alittlebitofmathcankeepasecretES" # 256-bit key (32 characters in utf-8)