import telebot
import logging
import requests
import multiprocessing
import time

import nvd_dist_gov

logging.basicConfig(filename="link_bot.log", level=logging.DEBUG,
                    format="%(asctime)s - [%(levelname)s]: %(message)s")
users = [1237392247]
modules = [nvd_dist_gov]
bot = telebot.TeleBot("")


@bot.message_handler(func=lambda message: message.chat.id in users, commands=['start'])
def welcome(message):
    bot.send_message(message.chat.id, "Успешно зарегистрирован, плотное держание в курсе активировано")


def check_thread():
    while True:
        for m in modules:
            content = m.get_new()
            if content:
                for u in users:
                    for el in content:
                        bot.send_message(u, el)
        time.sleep(15)


def bot_thread():
    try:
        bot.infinity_polling(timeout=10)
    except ConnectionError as e:
        logging.warning(str(e))
    except telebot.apihelper.ApiException as e:
        logging.warning(str(e))
    except requests.exceptions.ConnectionError as e:
        logging.warning(str(e))


if __name__ == "__main__":
    multiprocessing.set_start_method("spawn")
    check_proc = multiprocessing.Process(target=check_thread)
    check_proc.start()
    bot_proc = multiprocessing.Process(target=bot_thread)
    bot_proc.start()
