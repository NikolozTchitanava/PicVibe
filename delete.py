import os

if os.path.exists('site.db'):
    os.remove('site.db')

print("Database cleared!")
