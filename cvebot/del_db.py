import sqlite3

connection = sqlite3.connect("shared_base.db")
cursor = connection.cursor()
cursor.execute("DELETE FROM shared_base WHERE id='CVE-2021-4194'")
connection.commit()
connection = sqlite3.connect("nvd_dist_gov.db")
cursor = connection.cursor()
cursor.execute("DELETE FROM processed WHERE id='CVE-2021-4194'")
connection.commit()
