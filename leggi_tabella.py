import sqlite3

conn = sqlite3.connect("users.db")  # Apri il database
cursor = conn.cursor()

cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")  # Elenco tabelle
print(cursor.fetchall())

cursor.execute("SELECT * FROM users;")  # Leggi i dati di una tabella
print(cursor.fetchall())

conn.close()  # Chiudi la connessione