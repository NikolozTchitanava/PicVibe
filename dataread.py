import sqlite3

def view_database(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    def print_table(table_name):
        cursor.execute(f"SELECT * FROM {table_name}")
        rows = cursor.fetchall()
        print(f"\n{table_name}:\n")
        for row in rows:
            print(row)

    tables = ["users", "temp_users", "images", "likes"]

    for table in tables:
        print_table(table)

    conn.close()

db_path = 'site.db'
view_database(db_path)
