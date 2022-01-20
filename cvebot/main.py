import datetime
import sqlite3

import telebot
import logging
import requests
import multiprocessing
import time
import os.path
import json

import nvd_dist_gov
import cdocx

shared_state_filename = "shared_base.db"
tags_filename = "tags.db"
tags_db_prefix = "user_"
logging.basicConfig(filename="cve_bot.log", level=logging.INFO, format="%(asctime)s - [%(levelname)s]: %(message)s")
users = []
modules = [nvd_dist_gov]
nl = "\n"
bot = telebot.TeleBot("::::")

def shield_string(s):
    return s.replace("_", "\\_").replace("*", "\\*").replace("[", "\\[").replace("`", "\\`")

def check_list_in_descr(slist, s):
    for e in slist:
        if e[0] in s:
            return True
    return False

def get_message_id(slist, s):
    for e in slist:
        if e[0] in s:
            return e[1]
    return False

def add_share_state(cve_dict):
    connection = sqlite3.connect(shared_state_filename)
    cursor = connection.cursor()
    needable = ['affected', 'description', 'description_ru', 'solution', 'link', 'metrics',
                'appear_time', 'update_time']
    for n in needable:
        if n not in cve_dict:
            cve_dict[n] = ''
    cursor.execute(
        """INSERT INTO shared_base(id, affected, description, description_ru, solution, link, metrics, appear_time,
        update_time) VALUES(:id, :affected, :description,:description_ru,:solution,:link,:metrics,:appear_time,
        :update_time)""", cve_dict)
    connection.commit()


@bot.message_handler(func=lambda message: message.chat.id in users, commands=['start'])
def welcome(message):
    bot.send_message(message.chat.id, "Успешно зарегистрирован, плотное держание в курсе активировано")


@bot.message_handler(func=lambda message: message.chat.id in users, commands=['tag'])
def tagging(message):
    logging.info(f"User {message.chat.id} requested tag {message.text.strip()[5:]}")
    connection = sqlite3.connect(tags_filename)
    cursor = connection.cursor()
    cursor.execute("SELECT data FROM "+ str(tags_db_prefix+str(message.chat.id))+" WHERE tag='tag'")
    tags = cursor.fetchall()
    tag_value = message.text.strip()[5:]
    if check_list_in_descr(tags, tag_value):
        bot.send_message(message.chat.id, "Данный тэг уже отслеживается вами")
        logging.info(f"User {message.chat.id} already have {message.text.strip()[5:]}")
    else:
        cursor.execute("INSERT INTO "+str(tags_db_prefix+str(message.chat.id))+"(tag, data, msgid) VALUES('tag', :value, :msgid)",
                       {"value": tag_value, "msgid": message.message_id})
        connection.commit()
        bot.send_message(message.chat.id, "Добавлено отслеживание: {}".format(tag_value))
        logging.info(f"User {message.chat.id} added tag {message.text.strip()[5:]}")


@bot.callback_query_handler(func=lambda call: True)
def callback_inline(call):
    logging.info(f"Processing call with args {call.data}")
    call_data = call.data.split("#")
    call_data = {"cve":call_data[0],"module":call_data[1],"extention":call_data[2],"user":int(call_data[3])}
    if 'module' in call_data and 'cve' in call_data and 'extention' in call_data:
        if call_data['extention'] == "docx":
            cve_dict = {"id": call_data['cve']}
            #call.data['module'].enrich_base(cve_dict)
            getattr(globals()[call_data['module']], 'enrich_base')(cve_dict)
            sending_filename = cdocx.write_cve_to_docx(cve_dict)
            with open(sending_filename,'rb') as sending_doc:
                bot.send_document(call_data['user'], data=sending_doc) #filename=os.path.basename(sending_filename))


def init_tags_db(users):
    if not os.path.exists(tags_filename):
        conn = sqlite3.connect(tags_filename)
        cursor = conn.cursor()
        for u in users:
            cursor.execute("CREATE TABLE "+str(tags_db_prefix+str(u))+"(tag text, data text, msgid text);")
        conn.commit()
    else:
        conn = sqlite3.connect(tags_filename)
        cursor = conn.cursor()
        for u in users:
            cursor.execute("CREATE TABLE IF NOT EXISTS "+str(tags_db_prefix+str(u))+"(tag text, data text, msgid text);")
        conn.commit()


def check_thread():
    init_tags_db(users)
    while True:
        for m in modules:
            content = m.get_new()
            print("+")
            if content:
                for el in content:
                    for u in users:
                        try:
                            connection = sqlite3.connect(tags_filename)
                            cursor = connection.cursor()
                            cursor.execute("SELECT data, msgid FROM "+ str(tags_db_prefix+str(u))+" WHERE tag='tag'")
                            tags = cursor.fetchall()
                            t = get_message_id(tags, el['description'])
                            keyboard = telebot.types.InlineKeyboardMarkup()
                            callback_button = telebot.types.InlineKeyboardButton(text=str(el['id'] + ".docx"),
                                                                             callback_data='#'.join([el['id'],m.__name__,'docx',str(u)]))

                            keyboard.add(callback_button)
                            #print(t)
                            if t:
                                ####print("[{te}](tg://user?id={u})\n")
                                bot.send_message(u,
                                         f"*{el['id']}*\n{shield_string('Affected: '+el['affected']+nl) if 'affected' in el else ''}*RU*: {shield_string(el['description_ru']) if 'description_ru' in el else 'N/A'} \n*EN*: {shield_string(el['description']) if 'description' in el else 'N/A'} \n{el['link'].split(nl)[0]}", parse_mode='Markdown',reply_to_message_id=t, reply_markup=keyboard)
                            else:
                                bot.send_message(u,
                                         f"*{el['id']}*\n{shield_string('Affected: '+el['affected']+nl) if 'affected' in el else ''}*RU*: {shield_string(el['description_ru']) if 'description_ru' in el else 'N/A'} \n*EN*: {shield_string(el['description']) if 'description' in el else 'N/A'} \n{el['link'].split(nl)[0]}", parse_mode='Markdown', disable_notification=True,reply_markup=keyboard)
                        except BaseException as e:
                            logging.error(str(e))
                            time.sleep(5)
                    add_share_state(el)
                    m.commit_state(el)
                logging.info("Committing of state finished")
        time.sleep(30)
        print("Sleep finished")


@bot.message_handler(func=lambda message: message.chat.id not in users, content_types=["text"])
def write_access(message):
    with open("access_log.txt", "a") as f:
        f.write(f"{datetime.datetime.now()} -- {message.chat.id} -- '{str(message)}' ")


def bot_thread():
    while True:
        try:
            bot.infinity_polling(timeout=10)
        except ConnectionError as e:
            logging.warning(str(e))
        except telebot.apihelper.ApiException as e:
            logging.warning(str(e))
        except requests.exceptions.ConnectionError as e:
            logging.warning(str(e))
        except BaseException as e:
            logging.warning(str(e))


if __name__ == "__main__":
#    try:
    multiprocessing.set_start_method("spawn")
    check_proc = multiprocessing.Process(target=check_thread, name="cve_bot_check")
    #check_proc.name = "cve_bot_check"
    check_proc.start()
    bot_proc = multiprocessing.Process(target=bot_thread, name="cve_bot_bot")
    bot_proc.start()
#    finally:
#        check_proc.terminate()
#        bot_proc.terminate()
