import tkinter
from tkinter import filedialog
from tkinter import *
import mp8xml
import json
from xlsxwriter import Workbook

main_window = tkinter.Tk()
main_window.title("Report transformer")
main_window.geometry("270x100+100+200")
main_window.minsize(270, 100)

LAST_CHOISE_SAVE = []
file_names = []
FULL_CHOISE_MAP = {"IP-адрес": "host_ip", "FQDN": "host_fqdn", "Наименование уязвимого ПО": "source",
                   "Версия уязвимого ПО": "version", "Уровень критичности": "level",
                   "Внутренний идентификатор уязвимости": "vulner_id", "Статус": "status",
                   "Время начала сканирования": "host_start_scan", "Время окончания сканирования": "host_stop_scan",
                   "Наименование уязвимости": "vulner_title", "Описание уязвимости": "description",
                   "Рекомендации по устранению": "how_to_fix", "Ссылки на дополнительную информацию": "links",
                   "Дата публикации уязвимости": "publication_date", "BID идентификаторы": "vulner_bid",
                   "CVE идентификаторы": "vulner_cve", "BDU идентификаторы": "vulner_fstec",
                   "OSVDB идентификаторы": "vulner_osvdb",

                   "cvss_temp_score": "cvss_temp_score", "cvss_base_score": "cvss_base_score",
                   "cvss_temp_score_decomp": "cvss_temp_score_decomp",
                   "cvss_base_score_decomp": "cvss_base_score_decomp", "cvss3_temp_score": "cvss3_temp_score",
                   "cvss3_base_score": "cvss3_base_score", "cvss3_temp_score_decomp": "cvss3_temp_score_decomp",
                   "cvss3_base_score_decomp": "cvss3_base_score_decomp"}
CHECK_BOX_GROUP = list(FULL_CHOISE_MAP.keys())
# CHECK_BOX_DICTIONARY = dict((x, 0) for x in CHECK_BOX_GROUP)
# CHECK_BOX_DICTIONARY = {point_name: tkinter.IntVar() for point_name in CHECK_BOX_GROUP}
label_info = tkinter.Label(main_window, text="Выберите файлы отчетов MP8")

CHECK_BOX = tkinter.Listbox(main_window, selectmode=EXTENDED, width=45, height=len(FULL_CHOISE_MAP))


def report_action():
    selected_sections = list(CHECK_BOX.curselection())
    current_scheme_of_writing = [list(FULL_CHOISE_MAP.values())[index] for index in selected_sections]
    saving_file = tkinter.filedialog.asksaveasfilename(
        filetypes=(("XLSX", "*.xlsx"), ("JSON", "*.json"))
    )
    result_base = []
    for inputs in file_names:
        result_base.extend(
            [{key: sub_dict[key] for key in current_scheme_of_writing if key in sub_dict} for sub_dict in
             list(mp8xml.process_report(inputs.name).values())]
        )
    if saving_file.endswith(".json"):
        with open(saving_file, 'w') as s:
            json.dump(result_base, s)
    if saving_file.endswith(".xlsx"):
        xlsx_workbook = Workbook(saving_file)
        worksheet = xlsx_workbook.add_worksheet("Vulnerabilities")
        headers_list = [list(FULL_CHOISE_MAP.keys())[index] for index in selected_sections]
        for h_index in range(len(headers_list)):
            worksheet.write(0, h_index, headers_list[h_index])
        tmp_row = 1
        for result_string in result_base:
            tmp_col = 0
            for header in current_scheme_of_writing:
                if header in result_string:
                    worksheet.write(tmp_row, tmp_col, result_string[header])
                tmp_col += 1
            tmp_row += 1
        xlsx_workbook.close()


report_button = tkinter.Button(main_window, text="Сформировать отчет", command=report_action)


def choose_file_action():
    global file_names
    file_names = tkinter.filedialog.askopenfiles(
        filetypes=(("XML файлы", "*.xml"),
                   ("Все файлы", "*.*")))
    main_window.geometry("270x540")
    main_window.minsize(270, 540)
    main_window.maxsize(290, 540)

    CHECK_BOX.insert(0, *CHECK_BOX_GROUP)
    CHECK_BOX.pack(padx=10, pady=10, expand=1)
    report_button.pack(expand=1)


choose_files_button = tkinter.Button(main_window, text="Выбрать файлы", command=choose_file_action)

# def process_checkbox():
#    for e in CHECK_BOX_DICTIONARY:
#        print(f"{e}: {CHECK_BOX_DICTIONARY[e].get()}", end=' ')
#    print()

# choose_files_button.grid(row=0, column=2, columnspan=2, sticky='n')

# choose_files_button.pack(side='left')
# choose_files_button.place(x=0, y=0)

# checkbox_frame = tkinter.Frame(main_window)
# NUMBER_OF_ROW = 2
# for e in CHECK_BOX_GROUP:
#    te = tkinter.Checkbutton(checkbox_frame, text=e,
#                              variable=CHECK_BOX_DICTIONARY[e],
#                              onvalue=1, offvalue=0)
#     te.grid(row=NUMBER_OF_ROW, column=0, columnspan=3, sticky='w', padx=10)
#     NUMBER_OF_ROW += 1
# checkbox_frame.grid(column=0, row=1, rowspan=NUMBER_OF_ROW - 1, sticky='w')

if __name__ == "__main__":
    label_info.pack(side='top')
    choose_files_button.pack(expand=1)
    main_window.mainloop()
