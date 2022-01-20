import sqlite3
import main


def init_shared_state_base():
    conn = sqlite3.connect(main.shared_state_filename)
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE shared_base(id text, affected text, description text, description_ru text, solution text,
         link text, metrics text, appear_time text, update_time text, PRIMARY KEY (id));
         """)
    conn.commit()


def init_nvd_state_bases():
    conn = sqlite3.connect("nvd_dist_gov.db")
    cursor = conn.cursor()
    cursor.execute(
        """CREATE TABLE processed(id text, affected text, description text, description_ru text, solution text,
         link text, metrics text, appear_time text, update_time text, PRIMARY KEY (id))""")
    conn.commit()
    cursor.execute(
        """CREATE TABLE testing(id text, affected text, description text, description_ru text, solution text,
         link text, metrics text, appear_time text, update_time text, PRIMARY KEY (id))""")
    conn.commit()
    cursor.execute(
        """CREATE TABLE skipping(id text, affected text, description text, description_ru text, solution text,
         link text, metrics text, appear_time text, update_time text, PRIMARY KEY (id))""")
    conn.commit()


if __name__ == "__main__":
    init_shared_state_base()
    init_nvd_state_bases()
